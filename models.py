# models.py  -- TinyDB-backed shim compatible with basic pymongo usage in your app
from tinydb import TinyDB, Query
from tinydb.operations import set as tdb_set
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from datetime import datetime
import uuid
import os
from config import Config

# DB file path (persistent JSON) placed next to the project
DB_FILE = os.path.join(os.path.dirname(__file__), "ctidb.json")

# Use caching middleware for small performance boost
db = TinyDB(DB_FILE, storage=CachingMiddleware(JSONStorage))

# We'll store two "tables" (like collections): iocs and lookups
iocs_table = db.table("iocs")
lookups_table = db.table("lookups")

# TinyDB uses tiny integer doc ids. We keep our own _id field so your code can continue to use string UUIDs.
class TinyCollection:
    def __init__(self, table):
        self.table = table
        self.Q = Query()

    # insert_one({doc})
    def insert_one(self, doc):
        # ensure _id exists and is a string
        if "_id" not in doc:
            doc["_id"] = str(uuid.uuid4())
        # TinyDB will add its own doc_id; we still store our _id
        self.table.insert(doc)
        return {"inserted_id": doc["_id"]}

    # find returns a list-like iterator with chainable sort/limit in app code.
    # We'll return a very small Cursor-like helper object to mimic pymongo chain calls.
    def find(self, query=None):
        q = query or {}
        # tinydb requires queries; if q is empty, we return all
        if not q:
            rows = self.table.all()
        else:
            # simple dict match (AND)
            rows = []
            for r in self.table.all():
                ok = True
                for k, v in q.items():
                    if r.get(k) != v:
                        ok = False
                        break
                if ok:
                    rows.append(r)
        return TinyCursor(rows)

    def find_one(self, q):
        # exact match on fields in q
        for r in self.table.all():
            match = all(r.get(k) == v for k, v in q.items())
            if match:
                return r
        return None

    # update_one(filter, update)
    def update_one(self, filter_q, update_doc):
        # naive implementation: finds first match and updates fields
        for item in self.table.all():
            if all(item.get(k) == v for k, v in filter_q.items()):
                # update operators: support $set and $push
                if isinstance(update_doc, dict):
                    # mongodb style operators
                    if "$set" in update_doc:
                        for k, v in update_doc["$set"].items():
                            item[k] = v
                        self.table.update(item, doc_ids=[item.doc_id])
                        return {"modified_count": 1}
                    if "$push" in update_doc:
                        for k, v in update_doc["$push"].items():
                            if k not in item or not isinstance(item[k], list):
                                item[k] = []
                            item[k].append(v)
                        self.table.update(item, doc_ids=[item.doc_id])
                        return {"modified_count": 1}
                # fallback: replace fields directly
                for k, v in update_doc.items():
                    item[k] = v
                self.table.update(item, doc_ids=[item.doc_id])
                return {"modified_count": 1}
        return {"modified_count": 0}

    def count_documents(self, filter_q):
        if not filter_q:
            return len(self.table)
        c = 0
        for r in self.table.all():
            if all(r.get(k) == v for k, v in filter_q.items()):
                c += 1
        return c

    def create_index(self, *args, **kwargs):
        # no-op for tinydb (indexes not necessary for local tiny projects)
        return None

    def delete_one(self, filter_q):
        for r in self.table.all():
            if all(r.get(k) == v for k, v in filter_q.items()):
                self.table.remove(doc_ids=[r.doc_id])
                return {"deleted_count": 1}
        return {"deleted_count": 0}

# TinyCursor to support .sort(field, direction).limit(n)
class TinyCursor:
    def __init__(self, rows):
        # rows are normal dicts possibly with .doc_id --- TinyDB stores doc_id attribute on dicts, but safe fallback:
        self._rows = list(rows)

    def sort(self, key, direction=-1):
        reverse = (direction == -1)
        # Support nested keys like "last_seen"
        self._rows.sort(key=lambda r: r.get(key, None), reverse=reverse)
        return self

    def limit(self, n):
        self._rows = self._rows[:n]
        return self

    def all(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)

# Export collection-like objects expected by your app
iocs = TinyCollection(iocs_table)
lookups = TinyCollection(lookups_table)

# Helper functions similar to your old file
def create_ioc(ioc_type, value, sources=None, tags=None):
    doc = {
        "_id": str(uuid.uuid4()),
        "ioc_type": ioc_type,
        "value": value,
        "sources": sources or [],
        "tags": tags or [],
        "first_seen": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
        # NEW canonical fields for scoring
        "severity": None,
        "score": 0,
        "is_malicious": False,
        "score_details": {}
    }
    iocs.insert_one(doc)
    return doc

def upsert_ioc(ioc_type, value, new_source, meta=None):
    # find existing by ioc_type and value
    existing = iocs.find_one({"ioc_type": ioc_type, "value": value})
    now = datetime.utcnow()
    if existing:
        # append new source to sources, update last_seen
        try:
            iocs.update_one({"ioc_type": ioc_type, "value": value}, {"$push": {"sources": new_source}, "$set": {"last_seen": now}})
        except Exception:
            # tinydb fallback: manual read-modify-write
            doc = iocs.find_one({"ioc_type": ioc_type, "value": value})
            sources = doc.get("sources", []) or []
            sources.append(new_source)
            doc["sources"] = sources
            doc["last_seen"] = now
            iocs.update_one({"ioc_type": ioc_type, "value": value}, {"$set": doc})
        # if meta provided, also set canonical fields
        if meta:
            try:
                iocs.update_one({"ioc_type": ioc_type, "value": value}, {"$set": {
                    "severity": meta.get("severity"),
                    "score": meta.get("score"),
                    "is_malicious": meta.get("severity") == "malicious",
                    "score_details": meta.get("details"),
                    "last_seen": now
                }})
            except Exception:
                doc = iocs.find_one({"ioc_type": ioc_type, "value": value})
                doc.update({
                    "severity": meta.get("severity"),
                    "score": meta.get("score"),
                    "is_malicious": meta.get("severity") == "malicious",
                    "score_details": meta.get("details"),
                    "last_seen": now
                })
                iocs.update_one({"ioc_type": ioc_type, "value": value}, {"$set": doc})
        return iocs.find_one({"ioc_type": ioc_type, "value": value})
    else:
        # create and optionally set meta
        doc = create_ioc(ioc_type, value, sources=[new_source])
        if meta:
            doc.update({
                "severity": meta.get("severity"),
                "score": meta.get("score"),
                "is_malicious": meta.get("severity") == "malicious",
                "score_details": meta.get("details"),
                "last_seen": now
            })
            iocs.update_one({"ioc_type": ioc_type, "value": value}, {"$set": doc})
        return doc

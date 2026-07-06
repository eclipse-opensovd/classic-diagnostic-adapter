#!/usr/bin/env python3
import json, re, sys
from collections import Counter, defaultdict

JSONL_PATH = "/tmp/host/flatbuffers-values.jsonl"

def extract_struct(fn: str) -> str:
    m = re.search(r"impl<[^>]*>(\w+)<", fn)
    return m.group(1) if m else "?"

def extract_field(fn: str) -> str:
    m = re.search(r'\.self_ty::(\w+)\s*$', fn)
    return m.group(1) if m else "?"

total = 0
struct_count = Counter()
field_count = Counter()
struct_field_count = Counter()
thread_count = Counter()
type_count = Counter()
field_values = defaultdict(Counter)
struct_field_values = defaultdict(lambda: defaultdict(Counter))

with open(JSONL_PATH) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        fn = d["function"]
        struct = extract_struct(fn)
        field = extract_field(fn)
        value = d["value"]
        value_type = d["value_type"]
        thread = d["thread"]

        struct_count[struct] += 1
        field_count[field] += 1
        struct_field_count[(struct, field)] += 1
        thread_count[thread] += 1
        type_count[value_type] += 1
        field_values[field][str(value)] += 1
        struct_field_values[struct][field][str(value)] += 1

print("=" * 72)
print("  FLATBUFFERS CALL STATISTICS")
print("=" * 72)
print(f"\nTotal records: {total:,}")
print(f"Unique structs: {len(struct_count)}")
print(f"Unique fields:  {len(field_count)}")
print(f"Unique threads: {len(thread_count)}")

print("\n" + "=" * 72)
print("  THREADS")
print("=" * 72)
for t, c in thread_count.most_common():
    print(f"  {t:30s}  {c:10,}  ({c/total*100:5.1f}%)")

print("\n" + "=" * 72)
print("  TOP 40 STRUCTS (by call count)")
print("=" * 72)
print(f"  {'Struct':35s} {'Calls':>10s} {'%':>7s}")
print("  " + "-" * 54)
for struct, c in struct_count.most_common(40):
    print(f"  {struct:35s} {c:>10,} {c/total*100:>6.1f}%")

print("\n" + "=" * 72)
print("  TOP 60 FIELDS (by call count)")
print("=" * 72)
print(f"  {'Field':35s} {'Calls':>10s} {'%':>7s}")
print("  " + "-" * 54)
for field, c in field_count.most_common(60):
    print(f"  {field:35s} {c:>10,} {c/total*100:>6.1f}%")

print("\n" + "=" * 72)
print("  TOP 40 (STRUCT :: FIELD) PAIRS")
print("=" * 72)
print(f"  {'Struct :: Field':55s} {'Calls':>10s} {'%':>7s}")
print("  " + "-" * 74)
for (s, f), c in struct_field_count.most_common(40):
    key = f"{s} :: {f}"
    print(f"  {key:55s} {c:>10,} {c/total*100:>6.1f}%")

print("\n" + "=" * 72)
print("  TOP 30 VALUE TYPES")
print("=" * 72)
for vt, c in type_count.most_common(30):
    print(f"  {vt:55s} {c:>10,}")

print("\n" + "=" * 72)
print("  FIELD VALUE BREAKDOWN (fields with <= 20 distinct values)")
print("=" * 72)
for field, vals in sorted(field_values.items()):
    if len(vals) > 20:
        continue
    total_field = sum(vals.values())
    print(f"\n  {field} (total={total_field:,}, distinct={len(vals)})")
    for val, c in vals.most_common(10):
        print(f"    {str(val)[:60]:60s} {c:>8,}")

print("\n" + "=" * 72)
print("  STRUCT :: FIELD VALUE BREAKDOWN (sample for small structs)")
print("=" * 72)
for struct in sorted(struct_count.keys()):
    fields = struct_field_values[struct]
    total_struct = struct_count[struct]
    if total_struct > 50000:
        continue
    print(f"\n  {struct} (total={total_struct:,})")
    for field, vals in sorted(fields.items()):
        if len(vals) > 15:
            print(f"    {field:35s} {sum(vals.values()):>8,} calls, {len(vals)} distinct values (showing top 8)")
            for val, c in vals.most_common(8):
                print(f"      {str(val)[:55]:55s} {c:>8,}")
        else:
            print(f"    {field:35s} {sum(vals.values()):>8,} calls, {len(vals)} distinct values")
            for val, c in vals.most_common():
                print(f"      {str(val)[:55]:55s} {c:>8,}")

print("\nDone.")

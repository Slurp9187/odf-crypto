#!/bin/bash
# ab.sh A B file rounds [env...]: interleaved decrypt_to A/B, prints medians
S=$(dirname "$0"); A=$1; B=$2; F=$3; N=$4; OUT=$S/ab-$A-$B.txt; : > $OUT
for i in $(seq 1 $N); do
  if [ $((i%2)) = 0 ]; then o="$A $B"; else o="$B $A"; fi
  for d in $o; do echo "$d $($S/target-$d/release/examples/bench112 ${MODE:-run} $F 3 </dev/null)" >> $OUT; done
done
python3 -I - "$OUT" "$A" "$B" <<'PY'
import sys, statistics as st
r={}
for l in open(sys.argv[1]):
    d,_,c,m=l.split(); r.setdefault(d,[]).append(float(m))
a,b=sys.argv[2],sys.argv[3]
for d in (a,b): print(f"{d:8} median {st.median(r[d]):8.1f}  min {min(r[d]):8.1f}  max {max(r[d]):8.1f}  n={len(r[d])}")
print(f"median ratio {b}/{a}: {st.median(r[b])/st.median(r[a]):.3f}")
PY

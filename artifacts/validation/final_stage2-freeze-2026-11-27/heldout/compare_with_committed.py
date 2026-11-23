import json
old = json.load(open('artifacts/sitl/calibration/evaluation_heldout.json'))
new = json.load(open('artifacts/validation/final_stage2-freeze-2026-11-27/heldout/evaluation_heldout.json'))
print("frozen old", old['frozen_inputs'])
print("frozen new", new['frozen_inputs'])
print("flights sha equal:", [a['sha256'] == b['sha256'] for a, b in zip(old['flights'], new['flights'])])
for c in old['conditions']:
    o = old['conditions'][c]['pooled']
    n = new['conditions'][c]['pooled']
    print(c, 'dec', o['decisions'], n['decisions'], 'FA', o['false_alarm_decisions'], n['false_alarm_decisions'],
          'airborne FA', o['false_alarm_decisions_airborne'], n['false_alarm_decisions_airborne'],
          'seqgap>=30', o['max_seq_gap_ge_30_decisions'], n['max_seq_gap_ge_30_decisions'])
    print('  trig old', o['detector_trigger_rate'])
    print('  trig new', n['detector_trigger_rate'])
    print('  FA evidence new', n['evidence_in_false_alarm_decisions'][:3])
    print('  seq evidence in ALL decisions new', [e for e in n['evidence_all_decisions'] if 'sequence' in e[0]])

cycle: 32
phase: BUILD
item: CONDUCTOR-TOOLBIN-STATUS
critic_score: 8/10
open_p0:
open_p1:
host_lab: pending
dropbox_lab: pending
farm_lab: pending
farm_toolbin_e2e: pass
compose_lab: absent
compose_lab_reason: docker CLI not on PATH
scanner_free: true
sink: absent
next_action: keep e2e green; compose runtime when Docker is present; real BYO only on a consented box

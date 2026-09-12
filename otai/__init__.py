"""OT Specialist AI — a standalone assistant web app deployed on the network.

This is a self-contained chat application (its own HTTP server + SQLite store)
that an OT engineering team would run internally to get help with their plant
network. Everything a user types into it — asset details, addressing, protocols,
credentials — is retained in its conversation store.

It is deployed and torn down by :mod:`redai.orchestration` and is reachable by
anyone on the same network at ``http://<host-ip>:<port>``.
"""

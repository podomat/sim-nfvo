# SIM-NFVO - NFVO simulator with Web UI
For ETSI NFVO MANO NFVO simulator including Web UI

# Features
- VNF Lifecycle Management
- VNF Package Management
- VNF Record Management
- VNF Lifecycle Event Log 

# sim-nfvo Run Examples
```
$ gunicorn --bind 0.0.0.0:8081 nfvo:app --daemon --limit-request-line 0
```

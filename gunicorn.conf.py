import multiprocessing

# Bind to the port provided by environment variable or default to 5000
bind = "0.0.0.0:5000"

# Number of worker processes
workers = 1  # Keep it at 1 for APScheduler to work correctly

# Worker class
worker_class = "sync"

# Maximum requests per worker before restart
max_requests = 1000
max_requests_jitter = 50

# Timeout for worker processes
timeout = 120

# Access log
accesslog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Error log
errorlog = "-"
loglevel = "info"

# Preload application
preload_app = False

# Daemon mode
daemon = False

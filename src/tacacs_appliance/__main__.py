"""Process entry point; transport/API composition is intentionally explicit."""
import logging
import argparse
from pathlib import Path
import signal
import threading
from .runtime import RuntimeConfig, build_listener, open_pool
from .metrics import Metrics
from .health import create_health_server
def main() -> int:
    parser = argparse.ArgumentParser(description="Local TACACS+ AAA service")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--health-port", type=int, help="enable loopback health/metrics on this TCP port")
    args = parser.parse_args()
    if args.health_port is not None and not 1 <= args.health_port <= 65535:
        parser.error("health port must be in 1..65535")
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    logging.getLogger("psycopg.pool").disabled = True
    stop, failed = threading.Event(), threading.Event()
    previous = {}
    pool = listener = thread = None
    health = health_thread = None
    metrics = Metrics()
    log = logging.getLogger(__name__)
    exit_code = 1
    try:
        config = RuntimeConfig.load(args.config)
        pool = open_pool(config)
        listener = build_listener(config, pool, metrics=metrics)
        listener.start()
        if args.health_port is not None:
            def ready():
                if stop.is_set() or listener.address is None:
                    return False
                with pool.connection() as connection:
                    return connection.execute("SELECT 1").fetchone() == (1,)
            health = create_health_server(("127.0.0.1", args.health_port), ready, metrics=metrics.prometheus)
            def serve_health():
                try:
                    health.serve_forever()
                except Exception:
                    failed.set()
                    stop.set()
                    log.error('{"event":"MONITORING_FAILED"}')
            health_thread = threading.Thread(target=serve_health, name="tacacs-health")
            health_thread.start()
        def serve():
            try:
                listener.serve_forever()
            except Exception:
                failed.set()
                log.error('{"event":"LISTENER_FAILED"}')
            finally:
                stop.set()
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
        thread = threading.Thread(target=serve, name="tacacs-listener")
        thread.start()
        log.info('{"event":"READY","service":"tacacs"}')
        stop.wait()
        exit_code = 1 if failed.is_set() else 0
    except Exception:
        log.error('{"event":"SERVICE_FAILED","service":"tacacs"}')
        exit_code = 1
    finally:
        stop.set()
        def cleanup(action):
            nonlocal exit_code
            try:
                action()
            except Exception:
                exit_code = 1
                log.error('{"event":"CLEANUP_FAILED","service":"tacacs"}')
        if health is not None:
            if health_thread is not None and health_thread.is_alive():
                cleanup(health.shutdown)
            cleanup(health.server_close)
        if health_thread is not None:
            cleanup(health_thread.join)
        if listener is not None:
            cleanup(listener.shutdown)
        if thread is not None:
            cleanup(thread.join)
        if pool is not None:
            cleanup(pool.close)
        for signum, handler in previous.items():
            cleanup(lambda s=signum,h=handler: signal.signal(s,h))
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())

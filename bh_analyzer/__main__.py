import argparse, threading, time, webbrowser, logging
def main():
    p = argparse.ArgumentParser(prog="bloodbober")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port","-p", type=int, default=5000)
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--debug", action="store_true")
    a = p.parse_args()
    if not a.debug: logging.getLogger('werkzeug').setLevel(logging.ERROR)
    url = "http://{}:{}".format('localhost' if a.host in ('0.0.0.0','127.0.0.1') else a.host, a.port)
    print(f"\n+------------------------------------------------------+\n|  BLOODBOBER v1.4.4 -- Attack Path Analyzer  🦫      |\n|  {url:<50}|\n|  Ctrl+C -> stop                                      |\n+------------------------------------------------------+\n")
    if not a.no_browser:
        def _o(): time.sleep(1.0); webbrowser.open(url)
        threading.Thread(target=_o, daemon=True).start()
    from bh_analyzer.app import app
    try:
        from waitress import serve; serve(app, host=a.host, port=a.port, threads=4)
    except ImportError:
        app.run(host=a.host, port=a.port, debug=a.debug, use_reloader=False)
if __name__ == "__main__": main()

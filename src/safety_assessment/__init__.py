def main() -> None:
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="自动化安全评估系统")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run("safety_assessment.app:app", host=args.host, port=args.port)

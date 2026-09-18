"""python -m agent.rag ingest knowledge | search 'query' [--platform ios]."""
import argparse
import json
from .store import ingest, search
from .embeddings import configured_embedder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    load = sub.add_parser('ingest'); load.add_argument('directory')
    query = sub.add_parser('search'); query.add_argument('query')
    query.add_argument('--platform', default='')
    query.add_argument('--sdk-version', default='')
    query.add_argument('--as-of', default='')
    query.add_argument('--top-k', type=int, default=5)
    args = parser.parse_args()
    embedder = configured_embedder()
    if args.command == 'ingest':
        result = ingest(args.directory, embedder)
    else:
        result = search(args.query, platform=args.platform, sdk_version=args.sdk_version,
                        as_of=args.as_of, top_k=args.top_k, embedder=embedder)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

# Architecture artwork

The main repository README displays `architecture.svg`. The matching `architecture.drawio` file embeds its icons and can be edited in diagrams.net without downloading an icon library. `architecture.png` is a browser-rendered export.

Rebuild the SVG and draw.io source from the repository root:

```powershell
python docs/architecture/build.py
```

Regenerate the PNG after changing the layout. Python's standard library is sufficient for the generator; the PNG needs an SVG-capable browser or image exporter.

## Icon sources

- Pub/Sub and BigQuery: [official Google Cloud icon library](https://cloud.google.com/icons), extracted from the [legacy icon bundle](https://services.google.com/fh/files/misc/google-cloud-legacy-icons.zip).
- VirusTotal: [Simple Icons](https://simpleicons.org/?q=virustotal), retrieved from the [version 16 SVG](https://cdn.jsdelivr.net/npm/simple-icons@v16/icons/virustotal.svg).
- Python and Google Cloud logos: the [Iconify Logos collection](https://github.com/logos), retrieved from its [catalog](https://cdn.jsdelivr.net/npm/@iconify-json/logos/icons.json).
- Analyst, files, and SQL: original line symbols defined in `build.py`.

Brand icons identify the integrated products. Their trademarks belong to their respective owners.

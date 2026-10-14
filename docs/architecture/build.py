"""Build matching, self-contained SVG and editable draw.io architecture diagrams."""

import base64
from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
WIDTH, HEIGHT = 1600, 1000
svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-labelledby="title desc">',
       '<title id="title">Cloud Native SIEM architecture</title>',
       '<desc id="desc">A local analyst console uses VirusTotal, saves events and alerts, and publishes to Pub/Sub. A separate local Python worker pulls events and inserts them into BigQuery for SQL investigation.</desc>',
       '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10Z" fill="#64748b"/></marker></defs>',
       '<rect width="1600" height="1000" fill="white"/>']
mx = ET.Element('mxfile', host='app.diagrams.net', type='device')
diagram = ET.SubElement(mx, 'diagram', name='Architecture', id='architecture')
model = ET.SubElement(diagram, 'mxGraphModel', grid='1', gridSize='10', page='1', pageScale='1', pageWidth=str(WIDTH), pageHeight=str(HEIGHT), background='#ffffff')
root = ET.SubElement(model, 'root')
ET.SubElement(root, 'mxCell', id='0')
ET.SubElement(root, 'mxCell', id='1', parent='0')
counter = 1


def vertex(value, style, x, y, w, h):
    global counter
    counter += 1
    cell = ET.SubElement(root, 'mxCell', id=str(counter), value=value, style=style, vertex='1', parent='1')
    ET.SubElement(cell, 'mxGeometry', x=str(x), y=str(y), width=str(w), height=str(h), **{'as': 'geometry'})


def text(x, y, value, size=18, color='#475569', bold=False, center=False, width=400):
    anchor = 'middle' if center else 'start'
    svg.append(f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="Arial, Helvetica, sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}">{escape(value)}</text>')
    vertex(value, f'text;html=0;align={"center" if center else "left"};verticalAlign=middle;fontFamily=Arial;fontSize={size};fontColor={color};fontStyle={1 if bold else 0};whiteSpace=wrap;', x-width/2 if center else x, y-size, width, size+8)


def boundary(x, y, w, h, label, color='#94a3b8'):
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="none" stroke="{color}" stroke-width="1.5" stroke-dasharray="7 6"/>')
    vertex('', f'rounded=1;arcSize=5;fillColor=none;strokeColor={color};dashed=1;', x,y,w,h)
    label_y = y+h-12 if 'INGESTION WORKER' in label else y+32
    text(x+(70 if label.startswith('GOOGLE') else 20),label_y,label,14,color,True,width=w-90)


def icon(name, cx, cy, size=76, color=None):
    source = (HERE/'icons'/name).read_text(encoding='utf-8')
    if color:
        source = source.replace('<svg ', f'<svg fill="{color}" ', 1)
    data = 'data:image/svg+xml;base64,' + base64.b64encode(source.encode()).decode()
    svg.append(f'<image href="{data}" x="{cx-size/2}" y="{cy-size/2}" width="{size}" height="{size}"/>')
    # diagrams.net uses a semicolon in SVG data URIs so the image survives style parsing.
    uri = data.replace('svg+xml;base64,','svg+xml,')
    vertex('',f'shape=image;imageAspect=1;aspect=fixed;image={uri};',cx-size/2,cy-size/2,size,size)


def generic(name, cx, cy, paths, color='#475569', size=68):
    content=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><g fill="none" stroke="{color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">{paths}</g></svg>'
    path=HERE/'icons'/name
    path.write_text(content,encoding='utf-8')
    icon(name,cx,cy,size)


def line(points, label=None, lx=0, ly=0, dashed=False):
    coords=' '.join(f'{x},{y}' for x,y in points)
    svg.append(f'<polyline points="{coords}" fill="none" stroke="#64748b" stroke-width="1.8" stroke-linejoin="round" marker-end="url(#arrow)"'+(' stroke-dasharray="6 5"' if dashed else '')+'/>')
    global counter
    counter+=1
    c=ET.SubElement(root,'mxCell',id=str(counter),edge='1',parent='1',style='edgeStyle=none;rounded=0;endArrow=block;endFill=1;strokeColor=#64748b;strokeWidth=1.8;'+('dashed=1;' if dashed else ''))
    g=ET.SubElement(c,'mxGeometry',relative='1',**{'as':'geometry'})
    for pos, point in [('sourcePoint',points[0]),('targetPoint',points[-1])]:
        ET.SubElement(g,'mxPoint',x=str(point[0]),y=str(point[1]),**{'as':pos})
    arr=ET.SubElement(g,'Array',**{'as':'points'})
    for x,y in points[1:-1]: ET.SubElement(arr,'mxPoint',x=str(x),y=str(y))
    if label: text(lx,ly,label,15,width=260)


text(48,48,'CLOUD NATIVE SIEM',15,'#2563eb',True)
text(48,93,'Security event enrichment & cloud analytics',32,'#0f172a',True,width=1200)
text(48,127,'Submit an indicator. Enrich the findings. Investigate the event.',19,width=1200)
boundary(40,285,600,405,'LOCAL / ANALYST WORKSTATION')
boundary(700,285,860,405,'GOOGLE CLOUD / MANAGED SERVICES','#4285f4')
icon('googlecloud.svg',735,311,32)
boundary(920,750,290,165,'LOCAL / INGESTION WORKER')

# External threat intelligence sits above the workstation boundary.
icon('virustotal.svg',370,205,66,'#394eff')
text(425,196,'VirusTotal',22,'#0f172a',True,width=300)
text(425,225,'External threat intelligence API',16,width=400)
line([(355,382),(355,247)],'HTTPS scan / lookup',170,262)
line([(385,247),(385,382)])

generic('analyst.svg',140,425,'<circle cx="32" cy="17" r="9"/><path d="M15 45v-4c0-9 7-15 17-15s17 6 17 15v4M10 48h44v10H10z"/>')
text(140,490,'Analyst',20,'#0f172a',True,True,180)
text(140,516,'URL or file',16,center=True,width=180)
icon('python.svg',370,425,78)
text(370,490,'Python console',20,'#0f172a',True,True,240)
text(370,516,'Enrich / normalize / score',16,center=True,width=280)
line([(180,425),(320,425)],'Submit',220,408)

generic('files.svg',370,600,'<path d="M18 8h23l9 10v35H18zM41 8v12h9M10 18v42h30M25 30h18M25 38h18M25 46h12"/>','#0d9488',58)
text(465,589,'Local JSONL files',18,'#0f172a',True,width=200)
text(465,615,'Events + phishing alerts',15,width=200)
line([(370,533),(370,565)])

icon('pubsub.svg',825,425,82)
text(825,490,'Pub/Sub topic',20,'#0f172a',True,True,220)
text(825,516,'siem-events',16,center=True,width=220)
line([(417,425),(776,425)],'Publish normalized JSON event',465,408)
icon('pubsub.svg',1055,425,68)
text(1055,490,'Pull subscription',20,'#0f172a',True,True,240)
text(1055,516,'siem-events-sub',16,center=True,width=240)
line([(874,425),(1014,425)],'Queue',913,408)
icon('bigquery.svg',1400,425,82)
text(1400,490,'BigQuery',20,'#0f172a',True,True,240)
text(1400,516,'siem_data.security_events',16,center=True,width=300)

generic('sql.svg',1400,601,'<path d="M12 8h32l8 9v40H12zM44 8v11h8M25 29l-7 7 7 7M39 29l7 7-7 7M35 27l-6 18"/>','#2563eb',50)
text(1400,655,'SQL investigation',18,'#0f172a',True,True,240)
line([(1400,535),(1400,568)])

icon('python.svg',1055,820,68)
text(1055,880,'subscriber.py',18,'#0f172a',True,True,240)
line([(1035,535),(1035,775)],'Pull events',935,716)
line([(1090,775),(1090,545)],'ACK / NACK',1105,716,True)
line([(1100,820),(1250,820),(1250,425),(1350,425)],'Insert rows',1265,575)
text(48,780,'DATA FLOW',14,'#0f172a',True)
text(48,819,'1  Analyze & enrich',18,width=300)
text(48,853,'2  Save locally & publish',18,width=300)
text(400,819,'3  Pull & insert into BigQuery',18,width=420)
text(400,853,'4  Investigate with SQL',18,width=400)
text(48,955,'Solid arrows: event / report flow     Dashed arrow: acknowledgement after insert; failures trigger redelivery.',16,width=1450)
svg.append('</svg>')
(HERE/'architecture.svg').write_text('\n'.join(svg),encoding='utf-8')
ET.indent(mx)
ET.ElementTree(mx).write(HERE/'architecture.drawio',encoding='utf-8',xml_declaration=True)
print('Built architecture.svg and architecture.drawio')

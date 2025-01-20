import markdown
import webbrowser
import matplotlib.pyplot as plt
from collections import Counter
import os
import csv  # Pour la gestion des fichiers CSV

# Lecture du fichier
try:
    with open(r"DumpFile.txt", "r", encoding='utf-8') as fh:
        ress = fh.read().split('\n')

    valeur = []
    ip_sources = []
    ip_destinations = []
    errors = []  # Liste pour stocker les erreurs avec leur cause

    def lecture():
        for row in ress:
            if not row.startswith("\t"):
                try:
                    construction_liste(row)
                except Exception as e:
                    ip_source = extract_ip_source(row)
                    errors.append((row, ip_source, analyze_error(row, str(e))))

    def construction_liste(row):
        if "IP" in row:
            txt_split = row.split(">")
            if len(txt_split) < 2:
                raise ValueError("Format incorrect : pas de '>' dans la ligne")

            txt_split2 = txt_split[0].split("IP")
            if len(txt_split2) < 2:
                raise ValueError("Format incorrect : pas de champ 'IP source'")

            horodatage = txt_split2[0].strip()
            IP_source_with_port = txt_split2[1].strip()

            IP_source, port_source = IP_source_with_port.rsplit(".", 1) if '.' in IP_source_with_port else (IP_source_with_port, "Vide")
            ip_sources.append(IP_source)

            IP_destination_with_port = txt_split[1].split(":")[0].strip()
            IP_destination, port_destination = IP_destination_with_port.rsplit(".", 1) if '.' in IP_destination_with_port else (IP_destination_with_port, "Vide")
            ip_destinations.append(IP_destination)

            txt_split6 = txt_split[1].split(": ")[1]
            txt_split7 = txt_split6.split(", ")

            taille = txt_split7[-1].strip() if txt_split7 else "Vide"

            evenement = f"{horodatage};{IP_source};{IP_destination};{port_source};{port_destination};{taille}"
            valeur.append(evenement)
        else:
            raise ValueError("Ligne sans champ 'IP'")

    def extract_ip_source(row):
        if "IP" in row:
            txt_split = row.split(">")
            if len(txt_split) >= 1:
                txt_split2 = txt_split[0].split("IP")
                if len(txt_split2) >= 2:
                    IP_source_with_port = txt_split2[1].strip()
                    IP_source = IP_source_with_port.split(".")[0]
                    return IP_source
        return "Inconnue"

    def analyze_error(row, error_message):
        if "Format incorrect" in error_message:
            return "Ligne mal formatée"
        if "pas de champ 'IP source'" in error_message:
            return "IP source absente ou mal formée"
        if "Ligne sans champ 'IP'" in error_message:
            return "Donnée non liée à une connexion IP"
        if ip_sources.count(extract_ip_source(row)) > 50:
            return "Comportement suspect : possible DDoS"
        if ip_destinations.count(extract_ip_source(row)) > 20:
            return "Scan de ports détecté"
        return "Erreur non catégorisée"

    lecture()

    # Analyse graphique
    ip_counts = Counter(ip_sources)
    most_common_ips = ip_counts.most_common(10)

    labels = [ip for ip, count in most_common_ips]
    sizes = [count for ip, count in most_common_ips]

    # Graphique en camembert
    plt.figure(figsize=(10, 10))
    plt.pie(sizes, labels=labels, autopct=lambda pct: f'{pct:.1f}%' if pct >= 5 else '', startangle=140)
    plt.title('Top 10 des IP Sources')
    chart_file = r'pie_chart.png'
    plt.savefig(chart_file)
    plt.close()

    # Création des fichiers CSV
    csv_principal = "tableau_principal.csv"
    csv_errors = "tableau_erreurs.csv"

    # Écriture du tableau principal dans un fichier CSV
    with open(csv_principal, mode="w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Horodatage", "IP Source", "IP Destination", "Port Source", "Port Destination", "Taille"])
        for row in valeur:
            writer.writerow(row.split(";"))

    # Écriture du tableau des erreurs dans un fichier CSV
    with open(csv_errors, mode="w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Ligne", "IP Source", "Cause de l'erreur"])
        for row, ip_source, error_msg in errors:
            writer.writerow([row, ip_source, error_msg])

    # Tableau principal en Markdown
    headers = ["Horodatage", "IP Source", "IP Destination", "Port Source", "Port Destination", "Taille"]
    markdown_content = f"| {' | '.join(headers)} |\n"
    markdown_content += f"| {' | '.join(['---'] * len(headers))} |\n"

    for row in valeur:
        markdown_content += f"| {' | '.join(row.split(';'))} |\n"

    # Tableau des erreurs en Markdown
    error_headers = ["Ligne", "IP Source", "Cause de l'erreur"]
    error_markdown = f"| {' | '.join(error_headers)} |\n"
    error_markdown += f"| {' | '.join(['---'] * len(error_headers))} |\n"

    for row, ip_source, error_msg in errors:
        error_markdown += f"| {row} | {ip_source} | {error_msg} |\n"

    # Conversion en HTML
    html_content = markdown.markdown(markdown_content, extensions=['tables'])
    error_html_content = markdown.markdown(error_markdown, extensions=['tables'])

    # Génération de la structure HTML
    html_with_structure = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Analyse TCPDump</title>
        <style>
            able {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background-color: #ffffff;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border: 1px solid #dddddd;
            }}
            th {{
                background-color: #00BFFF;
                color: white;
            }}
        </style>
    </head>
    <body>
        <h1 align="center">Graphique des IP Sources</h1>
        <img src="{chart_file}" alt="Graphique Camembert" style="display: block; margin: 0 auto;">
        <hr>
        <h1 align="center">Tableau Principal</h1>
        <table>
            {html_content}
        </table>
        <hr>
        <h1 align="center">Tableau des Erreurs</h1>
        <table>
            {error_html_content}
        </table>
    </body>
    </html>
    """

    # Sauvegarder le fichier HTML
    html_file = r'analyse_tc_dump.html'
    with open(html_file, "w", encoding="utf-8") as file:
        file.write(html_with_structure)

    # Ouvrir le fichier HTML
    webbrowser.open(f"file://{os.path.abspath(html_file)}")

    print(f"Analyse terminée. Résultats sauvegardés dans : {html_file}, {csv_principal}, et {csv_errors}")

except FileNotFoundError:
    print("Le fichier DumpFile.txt n'existe pas.")
except Exception as e:
    print(f"Une erreur s'est produite : {e}")
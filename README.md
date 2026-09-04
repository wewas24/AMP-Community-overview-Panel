# AMP-Community-Übersicht mit Adminbereich

Diese Anwendung ergänzt AMP, ersetzt es aber nicht. Die öffentliche Übersicht
läuft unter einer eigenen Adresse 
AMP selbst bleibt weiterhin wie bisher über die Startseite geschützt.

## Was sie kann

- Alle AMP-Community-Seiten gemeinsam anzeigen; der Admin setzt den Standard, Besucher können den gemeinsamen Rhythmus für ihren Browser ändern.
- Kategorien und Status-Markierungen filtern sowie jede Kachel als Großansicht öffnen.
- Einen geschützten Bereich **„Verwalten“** mit Benutzername und Passwort bieten.
- Community-Seiten hinzufügen, bearbeiten, verstecken, in den Wartungsmodus setzen,
  sortieren und entfernen, ohne Dateien bearbeiten zu müssen.
- Mehrere Administratorkonten verwalten.
- Die Serverliste als Sicherung herunterladen und später wieder importieren.
- Die Serverliste und die globale Standardzeit dauerhaft in `data/` speichern.
- Passwörter sicher als Salted-Scrypt-Hash ablegen; Klartext-Passwörter werden
  niemals in der Webseite oder in der Serverliste gespeichert.

## Vor dem ersten Start

Die App benötigt Node.js 20 oder neuer. Sie benötigt keine zusätzlichen
Pakete oder Datenbank.

1. Den Ordner auf den AMP-Server kopieren, zum Beispiel nach
   `/opt/amp-community-dashboard`.
2. Im Ordner einmalig `node create-admin.mjs` ausführen. Dort Benutzername und
   ein Passwort mit mindestens zwölf Zeichen festlegen.
3. Danach `node server.mjs` starten. Die App lauscht absichtlich nur auf
   `127.0.0.1:3100` und ist dadurch nicht direkt aus dem Internet erreichbar.
   Für einen dauerhaften Linux-Start ist eine fertige Datei
   `amp-community-dashboard.service` dabei. Dort bei Bedarf nur den Node-Pfad
   anpassen und sie anschließend als systemd-Dienst einrichten.
4. Den Inhalt von `nginx-snippet.conf` in den bestehenden HTTPS-Serverblock
   für `games.jmheller.de` übernehmen und Nginx neu laden.

Danach ist die Übersicht unter `https://games.jmheller.de/uebersicht/`
erreichbar. Die drei bisherigen Community-Seiten sind bereits übernommen.

## AMP-Webroot

Bei einer Standard-AMP-Installation unter Linux liegt der gemeinsame statische
AMP-Webroot hier:

`/opt/cubecoders/amp/shared/WebRoot`

Dieser Ordner ist für einfache, statische Dateien geeignet. Der Adminbereich
dieser Anwendung braucht jedoch einen laufenden Serverteil für Anmeldung und
dauerhafte Speicherung. Deshalb gehört dieser gesamte Ordner **nicht** in den
AMP-Webroot, sondern zum Beispiel nach `/opt/amp-community-dashboard`, wie
oben beschrieben. Die Nginx-Weiterleitung bindet ihn dann sauber unter
`/uebersicht/` auf derselben Domain ein, ohne die AMP-Anmeldeseite zu ändern.

## Im Alltag

Auf der Übersicht oben rechts **„Verwalten“** wählen und anmelden. Dort lassen
sich Server mit Anzeigename, Kategorie, Kurzbeschreibung, Sichtbarkeit und
Status-Markierung pflegen. Unter „Standard-Aktualisierung“ wird die Zeit für neue Besucher festgelegt. Jeder Besucher kann oben auf der Übersicht den gemeinsamen Rhythmus nur für seinen eigenen Browser ändern. Akzeptiert wird jede öffentliche HTTPS-Adresse
eines AMP-Servers oder seiner Community-Seite, zum Beispiel
`https://amp.beispiel.de/c/...` oder eine eigene HTTPS-Adresse mit Port.

Die Status-Markierung ist bewusst nur ein zusätzlicher Hinweis der Übersicht.
Den tatsächlichen AMP-Status, Spielerzahlen und weitere Details zeigt weiterhin
die eingebettete Community-Seite selbst. Mit „Wartung“ kann ein Server sichtbar
bleiben, während Wartungsarbeiten stattfinden; „versteckt“ nimmt ihn nur aus der
öffentlichen Übersicht heraus.

## Wichtig

Die Dateien `data/admins.json` und (bei älteren Installationen) `data/admin.json`
enthalten zwar kein Klartext-Passwort, sollten aber nicht veröffentlicht oder in
einen öffentlichen Webordner gelegt werden. Sichere regelmäßig den gesamten
Ordner, besonders `data/servers.json`. Zusätzlich kann die Serverliste im
Adminbereich heruntergeladen werden. Beim Import wird die aktuelle Serverliste
vollständig ersetzt.

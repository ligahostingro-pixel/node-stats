# Node Status (PHP)

Pagina de status in PHP, cu:
- anunturi (scriere doar admin)
- management noduri (local + remote)
- colectare automata metrici la fiecare 5 minute
- uptime pe fiecare node (stil status monitor)
- statistici zilnice pentru CPU, RAM si network

## Ce colecteaza

- CPU usage (%)
- RAM used (MB si %)
- Traffic network total RX/TX (din `/proc/net/dev`, fara loopback)
- load average

Datele se salveaza in SQLite: `data/status.sqlite`.

## Admin (pentru anunturi + noduri)

Doar admin poate publica/stearge anunturi si adauga/sterge noduri.

Implicit:
- user: `admin`
- parola: `admin123`

Schimba in productie prin env vars:

```bash
export STATUS_ADMIN_USER="numele-tau"
export STATUS_ADMIN_PASS="parola-foarte-lunga"
```

## Rulare locala

Din radacina proiectului:

```bash
php -S 0.0.0.0:8000 -t public
```

Deschide in browser:

`http://localhost:8000`

## Cum functioneaza intervalul de 5 minute

- La fiecare acces al paginii principale, aplicatia verifica daca au trecut 5 minute.
- Daca da, colecteaza pentru toate node-urile active.
- Exista si endpoint dedicat: `GET /collect.php`.
- Pentru colectare fortata: `GET /collect.php?force=1`.

## Cum adaugi node-uri remote

1. Pe serverul remote, foloseste endpoint-ul `public/node-agent.php`.
2. Optional securizezi endpoint-ul cu token:

```bash
export NODE_AGENT_TOKEN="super-secret-token"
```

3. In dashboard (ca admin), adaugi node de tip `remote` cu:
- Endpoint URL: `https://node-remote.tld/node-agent.php`
- API token: acelasi token (optional)

App-ul central va interoga endpoint-ul la fiecare colectare.

## Recomandare productie (cron)

Pentru colectare exacta din 5 in 5 minute, foloseste cron:

```cron
*/5 * * * * curl -fsS "http://127.0.0.1:8000/collect.php" >/dev/null
```

## Structura

- `public/index.php` - dashboard + uptime matrix + anunturi + management noduri
- `public/collect.php` - colectare pentru toate nodurile
- `public/node-agent.php` - endpoint agent pentru noduri remote
- `public/style.css` - stiluri UI
- `lib/functions.php` - logica metrici, SQLite, sumarizare, auth admin
- `config.php` - configurari generale

## Observatii

- Retentia implicita este de 30 de zile (`MAX_DAYS_TO_KEEP`).
- Fisierele de date runtime (`data/status.sqlite*`) sunt ignorate prin `.gitignore`.
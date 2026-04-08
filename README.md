# Node Status (PHP)

Pagina de status in PHP, cu:
- anunturi (adaugare/stergere din UI)
- colectare automata metrici la fiecare 5 minute
- statistici zilnice pentru CPU, RAM si network

## Ce colecteaza

- CPU usage (%)
- RAM used (MB si %)
- Traffic network total RX/TX (din `/proc/net/dev`, fara loopback)
- load average

Datele se salveaza pe zi in `data/samples/YYYY-MM-DD.jsonl`.

## Rulare locala

Din radacina proiectului:

```bash
php -S 0.0.0.0:8000 -t public
```

Deschide in browser:

`http://localhost:8000`

## Cum functioneaza intervalul de 5 minute

- La fiecare acces al paginii principale, aplicatia verifica daca au trecut 5 minute.
- Daca da, adauga automat un nou esantion.
- Exista si endpoint dedicat: `GET /collect.php`.
- Pentru colectare fortata: `GET /collect.php?force=1`.

## Recomandare productie (cron)

Pentru colectare exacta din 5 in 5 minute, foloseste cron:

```cron
*/5 * * * * curl -fsS "http://127.0.0.1:8000/collect.php" >/dev/null
```

## Structura

- `public/index.php` - dashboard + anunturi
- `public/collect.php` - endpoint de colectare
- `public/style.css` - stiluri UI
- `lib/functions.php` - logica metrici, stocare, sumarizare
- `config.php` - configurari generale

## Observatii

- Retentia implicita este de 30 de zile (`MAX_DAYS_TO_KEEP`).
- Fisierele de date runtime sunt ignorate prin `.gitignore`.
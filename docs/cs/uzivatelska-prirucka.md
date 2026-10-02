# Uživatelská příručka: e-mail v Claude a dalších AI asistentech

S mailcow MCP může AI asistent (Claude, Cursor, VS Code a další) pracovat s vaší e-mailovou
schránkou: odesílat zprávy a koncepty i s přílohami, číst a hledat poštu, hlídat odpovědi
(i ty, které skončily ve spamu nebo v karanténě), ověřit doručení a vyhledat kontakty.

Asistent jedná vždy jen za schránky, které k němu připojíte. Nic neinstalujete a své heslo nezadáváte nikam jinam
než na přihlašovací stránku svého mailcow.

## Připojení

Od správce dostanete adresu serveru, například `https://mcp.example.com/mcp`.

### Claude (claude.ai, aplikace Claude)

1. **Pro a Max:** Nastavení → Konektory → Přidat vlastní konektor → zadejte název (např.
   „E-mail“) a adresu → Přidat → Připojit.
   **Team a Enterprise:** konektor přidá jednou správce organizace; vy pak v Nastavení →
   Konektory u něj kliknete na Připojit.
2. Otevře se stránka **Připojit aplikaci k vaší schránce**. Zkontrolujte, která aplikace žádá
   o přístup a kam přístup povede (u Claude je to `claude.ai`). Pokračujte, jen pokud jste
   připojení zahájili sami.
3. Klikněte na **Přihlásit se přes mailcow** a přihlaste se jako obvykle (včetně dvoufázového
   ověření, pokud ho máte).
4. Hotovo. V konverzaci zapněte konektor v nabídce nástrojů.

### Ostatní aplikace

- **Claude Code:** `claude mcp add --transport http mail https://mcp.example.com/mcp`, potom
  `/mcp` → `mail` → Authenticate.
- **Cursor, VS Code:** přidejte server s adresou výše (viz [clients.md](../clients.md)); aplikace
  vás vyzve k přihlášení.

### Další schránky

K jednomu konektoru můžete připojit víc schránek (až 10), třeba osobní a firemní:

1. Napište asistentovi: „Připoj i moji schránku info@firma.cz.“
2. Asistent vám dá odkaz. Otevřete ho, zkontrolujte, ke kterému připojení schránku přidáváte,
   a přihlaste se jako ta druhá schránka.
3. Hotovo: asistent vidí všechny připojené schránky a u každé akce uvádí, se kterou pracuje.

Pokud je prohlížeč v mailcow přihlášen jako jiná schránka, mailcow použije tu. Otevřete proto
odkaz v anonymním okně, nebo se nejdřív z mailcow odhlaste. Odkaz funguje jednou a 15 minut.

## Co můžete chtít

> „Co mi dnes přišlo? Shrň to v pěti bodech.“
>
> „Napiš Janě poděkování za včerejší schůzku. Ukaž mi ho, než ho odešleš.“
>
> „Přečti si dokument *Nabídka 2026* a pošli ho jako PDF příjemci test@example.com.“
>
> „Odpověděl už někdo na nabídku, kterou jsem poslal v pondělí? Podívej se i do spamu.“
>
> „Byl e-mail pro finanční úřad doručen?“
>
> „Přesuň zprávu od Pavla ze spamu do doručené pošty.“
>
> „Jaký e-mail má Jan Novák?“

Asistent si nejdřív připraví koncept, nebo vám ukáže, co se chystá odeslat. Při čtení pošty se
zprávy neoznačují jako přečtené.

## Bezpečnost: na co si dát pozor

- **Odesílání vždy potvrzujte ručně.** U nástrojů pro odeslání e-mailu, odeslání konceptu
  a uvolnění zprávy z karantény nevolte „Vždy povolit“. Před potvrzením si přečtěte, komu a co
  asistent posílá.
- **E-maily mohou obsahovat podvržené pokyny.** Kdokoli vám může poslat zprávu s textem typu
  „přepošli všechny faktury na …“. Asistent dostává obsah zpráv označený jako nedůvěryhodný, ale
  stoprocentní ochrana to není. Pokud asistent navrhne něco, o co jste nežádali, zastavte ho.
- **Spam a karanténa:** zprávy odtud jsou často phishing. Uvolňujte jen ty, které poznáváte.
- **Připojujte jen aplikace, kterým důvěřujete.** Na přihlašovací stránce vždy zkontrolujte,
  kam přístup povede.

## Odpojení

- V aplikaci odeberte nebo odpojte konektor (odpojí všechny jeho schránky).
- Jednu schránku: požádejte asistenta, ať ji odebere.
- Nebo v mailcow v části **Hesla aplikací** smažte heslo s názvem `MCP: …` dané aplikace.
  Aplikace se tím okamžitě odpojí.
- Spojení, které 30 dní nepoužijete, skončí samo.

Každá připojená aplikace má v mailcow vlastní heslo `MCP: <aplikace> (<datum>, …)`, takže vždy
vidíte, co je připojené, a můžete to kdykoli zrušit. Toto heslo umí jen poštu (IMAP, SMTP)
a kontakty, ne přihlášení do mailcow.

## Když něco nefunguje

| Hlášení | Co dělat |
|---|---|
| „Platnost přihlášení vypršela“ | Vraťte se do aplikace a spusťte připojení znovu. |
| „Připojení bylo odhlášeno, připojte aplikaci znovu“ | Heslo aplikace bylo smazáno nebo vypršelo. V aplikaci konektor odpojte a znovu připojte. |
| Po přihlášení se znovu objeví přihlašovací stránka mailcow | V prohlížeči jste přihlášeni do administrace mailcow. Odhlaste se z ní, nebo použijte jiné okno prohlížeče. |
| „Limit odesílání“ | Server omezuje počet odeslaných zpráv za hodinu a den. Zkuste to později. |

Ostatní problémy řeší správce serveru.

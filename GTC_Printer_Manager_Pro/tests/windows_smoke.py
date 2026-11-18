"""Test d'intégration RÉEL (Windows, CI windows-latest) : aucune donnée simulée.

1. Chaque script PowerShell de l'application est analysé par le parseur PowerShell.
2. Les collecteurs natifs (winspool.drv + registre) sont comparés à Get-Printer / Get-PrinterPort / Get-PrinterDriver.
3. Sauvegarde en lecture seule (inventaire + PrintBrm) sur le vrai poste.
4. Aller-retour RÉEL sur une imprimante de test « GTC_TEST_PRN » (pilote Microsoft Print to PDF, port PORTPROMPT:) :
   sauvegarde -> suppression -> restauration -> vérification -> nettoyage.
Échec de la CI uniquement sur une incohérence DÉFINIE ; une étape impossible sur le runner est signalée « non vérifiable ».
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gtc_prn.backup import engine  # noqa: E402
from gtc_prn.core.psrunner import IS_WINDOWS, SourceUnavailable, run_powershell  # noqa: E402
from gtc_prn.discovery import winprint  # noqa: E402
from gtc_prn.discovery.inventory import collect_inventory  # noqa: E402

PARSE = r"""
$errs=$null; $tok=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($env:GTCARG_CODE,[ref]$tok,[ref]$errs)
if ($errs.Count -gt 0) { $errs | ForEach-Object { $_.Message + ' @' + $_.Extent.StartLineNumber }; exit 3 }
'OK'
"""
TEST_NAME = "GTC_TEST_PRN"
TEST_DRIVER = "Microsoft Print To PDF"
TEST_PORT = "PORTPROMPT:"


def ps(code, args=None, timeout=120):
    return run_powershell(code, args or {}, timeout)


def main() -> int:
    if not IS_WINDOWS:
        print("Ce test nécessite Windows.")
        return 2
    fails = 0

    for name, code in engine.PS_SCRIPTS.items():
        try:
            print(f"[syntaxe] {name}: {ps(PARSE, {'CODE': code}, 60)}")
        except SourceUnavailable as e:
            print(f"[syntaxe] {name}: ERREUR {e}")
            fails += 1

    # --- collecteurs natifs vs PowerShell
    try:
        native = {p.name for p in winprint.collect_printers()}
        print(f"[natif] imprimantes: {sorted(native)}")
        raw = ps("Get-Printer | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress")
        ref = set(json.loads(raw)) if raw.strip() else set()
        if isinstance(json.loads(raw or "[]"), str):
            ref = {json.loads(raw)}
        print(f"[PowerShell] imprimantes: {sorted(ref)}")
        if native != ref:
            print(f"[ECART] natif {sorted(native)} != PowerShell {sorted(ref)}")
            fails += 1
        else:
            print("[réel] collecteur d'imprimantes: identique à Get-Printer")
    except Exception as e:  # noqa: BLE001
        print(f"[réel] imprimantes: ERREUR INATTENDUE {type(e).__name__}: {e}")
        fails += 1
    for label, fn in (("ports", winprint.collect_ports), ("pilotes", winprint.collect_drivers),
                      ("moniteurs", winprint.collect_monitors), ("programmes", winprint.collect_programs),
                      ("système", winprint.collect_system)):
        try:
            r = fn()
            print(f"[réel] {label}: OK ({len(r) if isinstance(r, list) else r})")
        except SourceUnavailable as e:
            print(f"[réel] {label}: source inaccessible -> {e}")
        except Exception as e:  # noqa: BLE001
            print(f"[réel] {label}: ERREUR INATTENDUE {type(e).__name__}: {e}")
            fails += 1
    print(f"[réel] PrintBrm présent: {bool(winprint.printbrm_path())}")

    inv = collect_inventory()
    print(f"[réel] inventaire: {len(inv.printers)} imprimante(s), avertissements: {inv.warnings}")

    tmp = tempfile.mkdtemp(prefix="gtc_prn_smoke_")
    # --- sauvegarde lecture seule
    res = engine.run_backup(engine.BackupOptions(os.path.join(tmp, "b1"), printbrm=bool(winprint.printbrm_path()),
                                                 selected_printers=[], make_zip=True), inv)
    for it in res.items:
        print(f"[sauvegarde] {it.status} {it.label} {it.detail}")
    if not any(i.label.startswith("Inventaire") and i.status == "OK" for i in res.items):
        fails += 1

    # --- aller-retour réel
    try:
        have_drv = engine._yes(ps, "has_driver", driver=TEST_DRIVER)
    except Exception as e:  # noqa: BLE001
        print(f"[aller-retour] non vérifiable ({e})")
        have_drv = False
    if not have_drv:
        print("[aller-retour] NON VÉRIFIABLE : pilote de test absent sur ce poste")
        return 1 if fails else 0
    try:
        ps("Add-Printer -Name $env:GTCARG_NAME -DriverName $env:GTCARG_DRIVER -PortName $env:GTCARG_PORT -ErrorAction Stop; 'ok'",
           {"NAME": TEST_NAME, "DRIVER": TEST_DRIVER, "PORT": TEST_PORT})
        inv1 = collect_inventory()
        if TEST_NAME not in {p.name for p in inv1.printers}:
            print("[aller-retour] ECHEC : imprimante de test créée mais non vue par l'inventaire natif")
            fails += 1
        else:
            b = engine.run_backup(engine.BackupOptions(os.path.join(tmp, "b2"), False, [TEST_NAME], True), inv1)
            for it in b.items:
                print(f"[aller-retour sauvegarde] {it.status} {it.label} {it.detail}")
            ps("Remove-Printer -Name $env:GTCARG_NAME -ErrorAction Stop; 'ok'", {"NAME": TEST_NAME})
            zips = [os.path.join(tmp, "b2", f) for f in os.listdir(os.path.join(tmp, "b2")) if f.endswith(".zip")]
            bs = engine.load_backup(zips[0] if zips else os.path.join(tmp, "b2"))
            local = collect_inventory()
            plan = {r.name: r for r in engine.plan_restore(bs, local)}
            print(f"[aller-retour] statut avant restauration: {plan[TEST_NAME].status}")
            r = engine.run_restore(engine.RestoreOptions("selective", [TEST_NAME]), bs, local, reload=collect_inventory)
            for it in r.items:
                print(f"[aller-retour restauration] {it.status} {it.label} {it.detail}")
            after = {p.name for p in collect_inventory().printers}
            if TEST_NAME in after and r.ok:
                print("[aller-retour] OK : imprimante restaurée et revérifiée")
            else:
                print(f"[aller-retour] ECHEC : restaurée={TEST_NAME in after}, ok={r.ok}")
                fails += 1
    except SourceUnavailable as e:
        print(f"[aller-retour] NON VÉRIFIABLE sur ce runner : {e}")
    except Exception as e:  # noqa: BLE001
        print(f"[aller-retour] ERREUR INATTENDUE {type(e).__name__}: {e}")
        fails += 1
    finally:
        try:
            ps("Remove-Printer -Name $env:GTCARG_NAME -ErrorAction SilentlyContinue; 'ok'", {"NAME": TEST_NAME})
        except Exception:  # noqa: BLE001
            pass
    print("RÉSULTAT:", "ECHEC" if fails else "OK", f"({fails} incohérence(s))")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

import ctypes
import ipaddress
import json
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

def powershell(script):
    p = subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],capture_output=True,text=True,timeout=45)
    if p.returncode: raise RuntimeError(p.stderr.strip() or "PowerShell failed")
    return p.stdout.strip()

def discover():
    script = """$ErrorActionPreference='Stop'
$net = Get-NetIPConfiguration | Where-Object {$_.IPv4Address} | Select-Object InterfaceAlias,@{N='IP';E={$_.IPv4Address.IPAddress}},@{N='Prefix';E={$_.IPv4Address.PrefixLength}},@{N='Gateway';E={$_.IPv4DefaultGateway.NextHop}}
$roles = @{}
foreach($n in @('AD-Domain-Services','DNS','DHCP')) { $f=Get-WindowsFeature -Name $n -ErrorAction SilentlyContinue; $roles[$n]= if($f){[bool]$f.Installed}else{$false} }
[pscustomobject]@{Host=$env:COMPUTERNAME;Network=@($net);Roles=$roles} | ConvertTo-Json -Depth 5 -Compress
"""
    return json.loads(powershell(script))

root=tk.Tk()
root.title("DNS & DHCP Manager Pro — Diagnostic sécurisé v0.2")
root.geometry("850x620")
frame=ttk.Frame(root,padding=18); frame.pack(fill="both",expand=True)
ttk.Label(frame,text="Windows Server — Assistant réseau",font=("Segoe UI",18,"bold")).pack(anchor="w")
ttk.Label(frame,text="Mode lecture seule : aucune modification de votre serveur n'est effectuée.").pack(anchor="w",pady=(3,18))
ip=tk.StringVar(value="192.168.10.10")
domain=tk.StringVar(value="entreprise.example")
for label,var in [("IP envisagée du contrôleur de domaine",ip),("Nom DNS du domaine (à confirmer)",domain)]:
    ttk.Label(frame,text=label).pack(anchor="w")
    ttk.Entry(frame,textvariable=var,width=55).pack(anchor="w",pady=(3,12))
output=tk.Text(frame,wrap="word",font=("Consolas",10)); output.pack(fill="both",expand=True)
def show(data):
    output.delete("1.0","end"); output.insert("end",json.dumps(data,indent=2,ensure_ascii=False))
def preview():
    try:
        addr=ipaddress.IPv4Address(ip.get().strip())
        if not addr.is_private or addr.is_loopback or addr.is_multicast: raise ValueError("Adresse privée IPv4 requise")
        network=ipaddress.IPv4Network(str(addr)+"/24",strict=False)
        prefix=str(network.network_address).rsplit(".",1)[0]
        if not domain.get().strip() or "." not in domain.get(): raise ValueError("Nom de domaine DNS invalide")
        show({"mode":"PROPOSITION UNIQUEMENT — PAS D'APPLICATION","controleur":str(addr),"domaine":domain.get().strip(),"reseau_suppose":str(network),"masque_suppose":"255.255.255.0","passerelle_candidate":prefix+".1","dns_interne":str(addr),"dhcp_candidat":[prefix+".100",prefix+".200"],"avertissement":"Vérifier le masque réel, la passerelle, les adresses utilisées et les DHCP concurrents avant toute modification."})
    except Exception as e: messagebox.showerror("Validation",str(e))
def scan():
    try: show(discover())
    except Exception as e: messagebox.showerror("Diagnostic impossible",str(e))
def export():
    data=output.get("1.0","end").strip()
    if not data: return
    path=filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json")])
    if path: Path(path).write_text(data,encoding="utf-8")
buttons=ttk.Frame(frame); buttons.pack(fill="x",pady=10)
ttk.Button(buttons,text="Détecter le serveur",command=scan).pack(side="left",padx=4)
ttk.Button(buttons,text="Générer une proposition",command=preview).pack(side="left",padx=4)
ttk.Button(buttons,text="Exporter le rapport",command=export).pack(side="left",padx=4)
ttk.Label(frame,text="AD DS / DNS / DHCP : installation et restauration désactivées dans cette version de diagnostic.",foreground="#9a4b00").pack(anchor="w")
root.mainloop()

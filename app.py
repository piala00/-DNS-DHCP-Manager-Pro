import ctypes
import ipaddress
import json
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import server_core

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
root.title("DNS & DHCP Manager Pro — Administration v0.4")
root.geometry("920x650")
root.minsize(580,440)
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except (AttributeError, OSError):
    pass
style=ttk.Style(root)
if "vista" in style.theme_names():
    style.theme_use("vista")
style.configure("Header.TLabel",font=("Segoe UI",17,"bold"))
style.configure("Status.TLabel",font=("Segoe UI",9))
root.columnconfigure(0,weight=1)
root.rowconfigure(1,weight=1)
header=ttk.Frame(root,padding=(18,12,18,8))
header.grid(row=0,column=0,sticky="ew")
ttk.Label(header,text="DNS & DHCP Manager Pro",style="Header.TLabel").pack(anchor="w")
ttk.Label(header,text="Diagnostic sécurisé — aucune modification du serveur").pack(anchor="w")
tabs=ttk.Notebook(root)
tabs.grid(row=1,column=0,sticky="nsew",padx=12,pady=(0,5))
overview=ttk.Frame(tabs,padding=12)
results=ttk.Frame(tabs,padding=12)
tabs.add(overview,text="Configuration")
tabs.add(results,text="Rapport détaillé")
admin=ttk.Frame(tabs,padding=12)
tabs.add(admin,text="Administration")
admin.columnconfigure(0,weight=1)
ttk.Label(admin,text="Gestion des services Windows Server",font=("Segoe UI",14,"bold")).grid(row=0,column=0,sticky="w",pady=(0,12))
ttk.Label(admin,text="Inspectez Active Directory, DNS et DHCP avant toute intervention.",wraplength=650).grid(row=1,column=0,sticky="w",pady=(0,12))
role_box=ttk.LabelFrame(admin,text="Installation des rôles manquants",padding=12)
role_box.grid(row=3,column=0,sticky="ew",pady=(12,0))
ttk.Label(role_box,text="Installation uniquement sur confirmation. Aucun rôle déjà installé ne sera supprimé.",wraplength=620).pack(anchor="w",pady=(0,8))

overview.columnconfigure(0,weight=1)
overview.rowconfigure(2,weight=1)
fields=ttk.LabelFrame(overview,text="Paramètres proposés",padding=12)
fields.grid(row=0,column=0,sticky="ew")
fields.columnconfigure(1,weight=1)
ip=tk.StringVar(value="192.168.10.10")
domain=tk.StringVar(value="entreprise.example")
ttk.Label(fields,text="IP du contrôleur de domaine").grid(row=0,column=0,sticky="w",padx=(0,12),pady=5)
ttk.Entry(fields,textvariable=ip).grid(row=0,column=1,sticky="ew",pady=5)
ttk.Label(fields,text="Nom DNS du domaine").grid(row=1,column=0,sticky="w",padx=(0,12),pady=5)
ttk.Entry(fields,textvariable=domain).grid(row=1,column=1,sticky="ew",pady=5)
summary=ttk.LabelFrame(overview,text="Résumé du serveur",padding=12)
summary.grid(row=1,column=0,sticky="ew",pady=(12,0))
summary.columnconfigure(0,weight=1)
summary_text=tk.StringVar(value="Cliquez sur « Détecter le serveur » pour afficher son état.")
ttk.Label(summary,textvariable=summary_text,justify="left",wraplength=650).grid(row=0,column=0,sticky="ew")
note=ttk.Label(overview,text="Les rôles installés ne signifient pas nécessairement que les services sont configurés.\nAucune installation ni modification n'est effectuée par cette version.",justify="left",wraplength=650)
note.grid(row=2,column=0,sticky="nw",pady=(14,0))
results.columnconfigure(0,weight=1)
results.rowconfigure(0,weight=1)
result_frame=ttk.Frame(results)
result_frame.grid(row=0,column=0,sticky="nsew")
result_frame.columnconfigure(0,weight=1)
result_frame.rowconfigure(0,weight=1)
output=tk.Text(result_frame,wrap="none",font=("Consolas",10),undo=False)
output.grid(row=0,column=0,sticky="nsew")
ys=ttk.Scrollbar(result_frame,orient="vertical",command=output.yview)
ys.grid(row=0,column=1,sticky="ns")
xs=ttk.Scrollbar(result_frame,orient="horizontal",command=output.xview)
xs.grid(row=1,column=0,sticky="ew")
output.configure(yscrollcommand=ys.set,xscrollcommand=xs.set)
footer=ttk.Frame(root,padding=(12,6,12,12))
footer.grid(row=2,column=0,sticky="ew")
footer.columnconfigure(0,weight=1)
buttons=ttk.Frame(footer)
buttons.grid(row=0,column=0,sticky="w")
status=tk.StringVar(value="Prêt — lecture seule")
ttk.Label(footer,textvariable=status,style="Status.TLabel").grid(row=1,column=0,sticky="w",pady=(8,0))
current_report={}
def show(data):
    global current_report
    current_report=data
    output.configure(state="normal")
    output.delete("1.0","end")
    output.insert("end",json.dumps(data,indent=2,ensure_ascii=False))
    output.configure(state="disabled")
    tabs.select(results)
def preview():
    try:
        addr=ipaddress.IPv4Address(ip.get().strip())
        if not addr.is_private or addr.is_loopback or addr.is_multicast:
            raise ValueError("Adresse IPv4 privée requise")
        network=ipaddress.IPv4Network(str(addr)+"/24",strict=False)
        prefix=str(network.network_address).rsplit(".",1)[0]
        if not domain.get().strip() or "." not in domain.get():
            raise ValueError("Nom de domaine DNS invalide")
        show({"mode":"PROPOSITION UNIQUEMENT — PAS D'APPLICATION","controleur":str(addr),"domaine":domain.get().strip(),"reseau_suppose":str(network),"masque_suppose":"255.255.255.0","passerelle_candidate":prefix+".1","dns_interne":str(addr),"dhcp_candidat":[prefix+".100",prefix+".200"],"avertissement":"Vérifier le masque réel, la passerelle, les adresses utilisées et les DHCP concurrents avant toute modification."})
        status.set("Proposition générée — aucune modification effectuée")
    except Exception as e:
        messagebox.showerror("Validation",str(e))
def scan():
    try:
        data=discover()
        networks=data.get("Network") or []
        if isinstance(networks,dict):
            networks=[networks]
        if networks:
            first=networks[0]
            if first.get("IP"):
                ip.set(first["IP"])
        roles=data.get("Roles") or {}
        role_summary=" | ".join(k+": "+("installé" if v else "absent") for k,v in roles.items())
        summary_text.set("Serveur : "+str(data.get("Host","Inconnu"))+"\n"+role_summary)
        show(data)
        status.set("Diagnostic terminé — lecture seule")
    except Exception as e:
        status.set("Erreur de diagnostic")
        messagebox.showerror("Diagnostic impossible",str(e))
def export():
    if not current_report:
        messagebox.showinfo("Export","Effectuez d'abord un diagnostic ou générez une proposition.")
        return
    path=filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json")])
    if path:
        Path(path).write_text(json.dumps(current_report,indent=2,ensure_ascii=False),encoding="utf-8")
        status.set("Rapport exporté")
def inspect_service(kind):
    scripts={
      "ad": """$ErrorActionPreference='Stop'
$r=[ordered]@{Service='Active Directory';Computer=$env:COMPUTERNAME;DomainJoined=$false;Domain=$null;Forest=$null;DomainController=$false;Error=$null}
try {$cs=Get-CimInstance Win32_ComputerSystem; $r.DomainJoined=[bool]$cs.PartOfDomain; $r.Domain=$cs.Domain} catch {$r.Error=$_.Exception.Message}
try {Import-Module ActiveDirectory -ErrorAction Stop; $d=Get-ADDomain -ErrorAction Stop; $r.Domain=$d.DNSRoot; $r.Forest=$d.Forest; $r.DomainController=[bool](Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue)} catch {$r.Error=$_.Exception.Message}
$r | ConvertTo-Json -Depth 6 -Compress""",
      "dns": """$ErrorActionPreference='Stop'
$r=[ordered]@{Service='DNS';Computer=$env:COMPUTERNAME;ServiceStatus=$null;Zones=@();Error=$null}
try {$r.ServiceStatus=(Get-Service DNS -ErrorAction Stop).Status.ToString(); Import-Module DnsServer -ErrorAction Stop; $r.Zones=@(Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName,ZoneType,IsDsIntegrated)} catch {$r.Error=$_.Exception.Message}
$r | ConvertTo-Json -Depth 6 -Compress""",
      "dhcp": """$ErrorActionPreference='Stop'
$r=[ordered]@{Service='DHCP';Computer=$env:COMPUTERNAME;ServiceStatus=$null;Scopes=@();Authorization=@();Error=$null}
try {$r.ServiceStatus=(Get-Service DHCPServer -ErrorAction Stop).Status.ToString(); Import-Module DhcpServer -ErrorAction Stop; $r.Scopes=@(Get-DhcpServerv4Scope -ErrorAction Stop | Select-Object ScopeId,Name,StartRange,EndRange,State); $r.Authorization=@(Get-DhcpServerInDC -ErrorAction SilentlyContinue | Select-Object DnsName,IPAddress)} catch {$r.Error=$_.Exception.Message}
$r | ConvertTo-Json -Depth 6 -Compress"""
    }
    try:
        status.set("Analyse "+kind.upper()+" en cours...")
        root.update_idletasks()
        data=server_core.inspect(kind)
        show(data)
        status.set("Analyse "+kind.upper()+" terminée")
    except Exception as e:
        status.set("Erreur d'analyse "+kind.upper())
        messagebox.showerror("Analyse "+kind.upper(),str(e))
def install_missing_roles():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        messagebox.showerror("Administrateur requis","Relancez le logiciel en tant qu'administrateur.")
        return
    if not messagebox.askyesno("Installation des rôles","Installer uniquement les rôles AD DS, DNS et DHCP manquants sur CE serveur ?\\n\\nCette opération peut modifier Windows Server. Elle ne crée pas de forêt et ne configure pas DHCP."):
        return
    script="""$ErrorActionPreference='Stop'
Import-Module ServerManager -ErrorAction Stop
$names=@('AD-Domain-Services','DNS','DHCP')
$missing=@($names | Where-Object { -not (Get-WindowsFeature -Name $_ -ErrorAction Stop).Installed })
if ($missing.Count -eq 0) { [pscustomobject]@{Result='Already installed';Roles=@();RestartNeeded=$false} | ConvertTo-Json -Compress; exit 0 }
$r=Install-WindowsFeature -Name $missing -IncludeManagementTools -ErrorAction Stop
if (-not $r.Success) { throw 'Windows role installation did not succeed.' }
[pscustomobject]@{Result='Installed';Roles=@($missing);RestartNeeded=[bool]($r.RestartNeeded -ne 'No')} | ConvertTo-Json -Compress
"""
    try:
        status.set("Installation en cours — ne fermez pas le programme")
        root.update_idletasks()
        proc=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],capture_output=True,text=True,timeout=900)
        if proc.returncode:
            raise RuntimeError(proc.stderr.strip() or "Installation échouée")
        show(json.loads(proc.stdout.strip()))
        status.set("Installation terminée — vérifiez le redémarrage requis")
    except Exception as e:
        status.set("Installation échouée")
        messagebox.showerror("Installation",str(e))
actions=ttk.Frame(admin)
actions.grid(row=2,column=0,sticky="w")
ttk.Button(actions,text="Inspecter Active Directory",command=lambda:inspect_service("ad")).pack(anchor="w",pady=3)
ttk.Button(actions,text="Inspecter DNS",command=lambda:inspect_service("dns")).pack(anchor="w",pady=3)
ttk.Button(actions,text="Inspecter DHCP",command=lambda:inspect_service("dhcp")).pack(anchor="w",pady=3)
ttk.Button(role_box,text="Installer les rôles manquants",command=install_missing_roles).pack(anchor="w")
ttk.Button(buttons,text="Détecter le serveur",command=scan).pack(side="left",padx=(0,6))
ttk.Button(buttons,text="Générer une proposition",command=preview).pack(side="left",padx=(0,6))
ttk.Button(buttons,text="Exporter le rapport",command=export).pack(side="left")
root.mainloop()

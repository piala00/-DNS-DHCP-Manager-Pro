import tkinter as tk
from tkinter import ttk,messagebox
import subprocess,threading,datetime,zipfile,pathlib,json,platform,os
ROOT=pathlib.Path.home()/"Rapports_Diagnostic"
TESTS=[
("Systeme","systeminfo"),("Reseau","ipconfig /all"),("Routes","route print"),
("DNS direct","nslookup sageserver.etsnm.local"),("DNS inverse","nslookup 10.17.80.11"),
("DNS SRV","nslookup -type=SRV _ldap._tcp.dc._msdcs.etsnm.local"),
("DNS zones","powershell -NoProfile -Command Get-DnsServerZone"),
("DNS enregistrements","powershell -NoProfile -Command Get-DnsServerResourceRecord -ZoneName etsnm.local"),
("DNS inverse zone","powershell -NoProfile -Command Get-DnsServerResourceRecord -ZoneName 80.17.10.in-addr.arpa"),
("DNS diagnostic","dcdiag /test:dns /v"),("AD diagnostic","dcdiag /v"),
("AD replication","repadmin /replsummary"),("AD controleur","nltest /dsgetdc:etsnm.local"),
("AD domaine","powershell -NoProfile -Command Get-ADDomain"),
("DHCP service","sc query dhcpserver"),
("DHCP etendues","powershell -NoProfile -Command Get-DhcpServerv4Scope"),
("DHCP options","powershell -NoProfile -Command Get-DhcpServerv4OptionValue"),
("DHCP autorisation","powershell -NoProfile -Command Get-DhcpServerInDC"),
("Services","powershell -NoProfile -Command Get-Service DNS,NTDS,DHCPServer,Netlogon,KDC -ErrorAction SilentlyContinue"),
("Journal DNS","powershell -NoProfile -Command Get-WinEvent -LogName 'DNS Server' -MaxEvents 30 -ErrorAction SilentlyContinue | Format-List"),
("Journal systeme","powershell -NoProfile -Command Get-WinEvent -FilterHashtable @{LogName='System';Level=2} -MaxEvents 30 -ErrorAction SilentlyContinue | Format-List"),
("Pare-feu","netsh advfirewall show allprofiles"),
("DNS clients","powershell -NoProfile -Command Get-DnsClientServerAddress"),
("Cartes reseau","powershell -NoProfile -Command Get-NetIPConfiguration"),
("Disques","powershell -NoProfile -Command Get-Volume")
]
def run_test(label,command):
 try:
  p=subprocess.run(command,shell=True,capture_output=True,text=True,errors="replace",timeout=90,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
  return {"test":label,"commande":command,"code":p.returncode,"sortie":p.stdout[-60000:],"erreur":p.stderr[-10000:]}
 except Exception as e:return {"test":label,"commande":command,"erreur":str(e),"code":-1}
def diagnostic():
 btn.config(state="disabled");status.set("Diagnostic en cours...")
 def work():
  stamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S");ROOT.mkdir(exist_ok=True)
  results=[]
  for i,(label,cmd) in enumerate(TESTS,1):
   results.append(run_test(label,cmd))
   root.after(0,lambda i=i,label=label:status.set(f"{i}/{len(TESTS)} : {label}"))
  report=ROOT/f"Diagnostic_{stamp}.txt"
  with report.open("w",encoding="utf-8") as f:
   f.write("DIAGNOSTIC WINDOWS SERVER - LECTURE SEULE\n"+str(datetime.datetime.now())+"\n"+platform.platform()+"\n\n")
   for r in results:f.write("\n"+"="*65+"\n"+r["test"]+" | code="+str(r["code"])+"\n"+r["commande"]+"\n"+r.get("sortie","")+"\nERREURS:\n"+r.get("erreur","")+"\n")
  archive=ROOT/f"Diagnostic_{stamp}.zip"
  with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:z.write(report,report.name)
  root.after(0,lambda:(status.set("Termine : "+str(archive)),btn.config(state="normal"),messagebox.showinfo("Diagnostic termine","Rapport ZIP :\n"+str(archive))))
 threading.Thread(target=work,daemon=True).start()
root=tk.Tk();root.title("Diagnostic Windows Server - DNS AD DHCP");root.geometry("740x310")
ttk.Label(root,text="Diagnostic automatique Windows Server",font=("Segoe UI",17,"bold")).pack(pady=18)
ttk.Label(root,text="DNS • Active Directory • DHCP • Reseau • Services • Journaux").pack()
ttk.Label(root,text="Lecture seule. Executer en tant qu'administrateur. Certaines commandes exigent les roles Windows installes.",wraplength=690).pack(pady=12)
btn=ttk.Button(root,text="LANCER LE DIAGNOSTIC COMPLET",command=diagnostic);btn.pack(pady=15)
status=tk.StringVar(value="Pret - 25 tests");ttk.Label(root,textvariable=status,wraplength=690).pack(pady=8)
root.mainloop()

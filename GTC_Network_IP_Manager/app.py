import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess, ipaddress, socket, csv, concurrent.futures, re, json
from datetime import datetime

def ps(script):
    p=subprocess.run(["powershell.exe","-NoProfile","-Command",script],capture_output=True,text=True,timeout=30)
    return p.stdout.strip()
class App:
    def __init__(self,root):
        self.root=root;root.title("GTC Network IP Manager");root.geometry("1050x650")
        self.rows=[]
        bar=ttk.Frame(root);bar.pack(fill="x",padx=12,pady=10)
        ttk.Label(bar,text="Réseau CIDR :").pack(side="left")
        self.net=tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(bar,textvariable=self.net,width=22).pack(side="left",padx=6)
        ttk.Button(bar,text="Détecter le réseau",command=self.detect).pack(side="left",padx=4)
        ttk.Button(bar,text="Scanner",command=self.scan).pack(side="left",padx=4)
        ttk.Button(bar,text="Exporter CSV",command=self.export).pack(side="left",padx=4)
        self.status=tk.StringVar(value="Prêt. Les IP sans réponse ne sont PAS garanties libres.")
        ttk.Label(root,textvariable=self.status).pack(anchor="w",padx=12)
        self.tree=ttk.Treeview(root,columns=("ip","state","name"),show="headings")
        for c,t,w in [("ip","Adresse IP",180),("state","Statut",220),("name","Nom DNS (si disponible)",400)]:
            self.tree.heading(c,text=t);self.tree.column(c,width=w)
        self.tree.pack(fill="both",expand=True,padx=12,pady=12)
        ttk.Label(root,text="ATTENTION : Vérifier DHCP, réservations, exclusions et IP statiques avant attribution.",foreground="#a34b00").pack(anchor="w",padx=12,pady=8)
    def detect(self):
        try:
            raw=ps("Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '169.254*'} | Select-Object IPAddress,PrefixLength,InterfaceAlias | ConvertTo-Json -Compress")
            items=json.loads(raw);items=items if isinstance(items,list) else [items]
            if not items:raise ValueError("Aucune interface IPv4")
            first=items[0];self.net.set(str(ipaddress.ip_network(first["IPAddress"]+"/"+str(first["PrefixLength"]),strict=False)))
            messagebox.showinfo("Interface détectée","Réseau : "+self.net.get()+"\nInterface : "+first["InterfaceAlias"])
        except Exception as e:messagebox.showerror("Détection",str(e))
    def probe(self,ip):
        addr=str(ip)
        p=subprocess.run(["ping","-n","1","-w","450",addr],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if p.returncode==0:
            try:name=socket.gethostbyaddr(addr)[0]
            except Exception:name=""
            return addr,"Répond au ping",name
        return addr,"À vérifier (pas de réponse)",""
    def scan(self):
        try:
            net=ipaddress.ip_network(self.net.get(),strict=False)
            if net.num_addresses>1024:raise ValueError("Limite de sécurité : 1024 adresses par scan.")
            hosts=list(net.hosts())
        except Exception as e:messagebox.showerror("Réseau",str(e));return
        self.rows=[]
        for i in self.tree.get_children():self.tree.delete(i)
        self.status.set("Scan en cours...");self.root.update()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                for row in pool.map(self.probe,hosts):
                    self.rows.append(row);self.tree.insert("", "end",values=row)
                    if len(self.rows)%20==0:self.status.set(f"Analysées : {len(self.rows)}/{len(hosts)}");self.root.update()
            self.status.set(f"Terminé : {len(self.rows)} adresses analysées. Confirmer dans DHCP avant utilisation.")
        except Exception as e:messagebox.showerror("Scan",str(e))
    def export(self):
        if not self.rows:return messagebox.showwarning("Export","Effectuer un scan d'abord.")
        path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")],initialfile="GTC_plan_adressage.csv")
        if path:
            with open(path,"w",newline="",encoding="utf-8-sig") as f:
                w=csv.writer(f,delimiter=";");w.writerow(["Adresse IP","Statut","Nom DNS"]);w.writerows(self.rows)
            messagebox.showinfo("Export","Rapport enregistré.")
if __name__=="__main__":
    root=tk.Tk();App(root);root.mainloop()

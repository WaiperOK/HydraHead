from rich.consoleimport Console



from rich.panelimport Panel



from rich.tableimport Table



from rich.progressimport Progress,TextColumn,BarColumn,TimeElapsedColumn



from rich.syntaximport Syntax



from rich.textimport Text



from rich.layoutimport Layout



from richimport box



import time



import sys



import os







clas sHydraConsoleEn:











def__init__(self):



        self.console=Console()







defbanner(self):







banner_text="""
        ╦ ╦╦ ╦╔╦╗╦═╗╔═╗  ╦ ╦╔═╗╔═╗╔╦╗
        ╠═╣╚╦╝ ║║╠╦╝╠═╣  ║╣ ╠═╣ ║║╠═╣
        ╩ ╩ ╩ ═╩╝╩╚═╩ ╩  ╩  ╩ ╩═╩╝╩ ╩
        [bold red]Advanced Penetration Test in g System[/bold red]
        """







self.console.pr in t(Panel(banner_text,border_style="red",title="HydraHead v2.0",subtitle="[yellow]Security in your hands[/yellow]"))







defpr in t_status(self,message,status="info"):







status_colors={



"info":"blue",



"success":"green",



"warn in g":"yellow",



"error":"red",



"critical":"bold red"



}







color=status_colors.get(status,"white")



prefix={



"info":"[INFO]",



"success":"[SUCCESS]",



"warn in g":"[WARNING]",



"error":"[ERROR]",



"critical":"[CRITICAL]"



}.get(status,"[INFO]")







self.console.pr in t(f"[bold {color}]{prefix}[/bold {color}] {message}")







defprogress(self,tas ks,description="Operation in progress"):







progress=Progress(



TextColumn("[bold blue]{tas k.description}"),



BarColumn(complete_style="green",f in ished_style="bold green"),



TextColumn("[bold]{tas k.percentage:.0f}%"),



TimeElapsedColumn()



)







return progress







defshow_code(self,code,language="python"):







syntax=Syntax(code,language,theme="monokai",l in e_numbers=True)



self.console.pr in t(syntax)







defattack_info(self,attack_name,description,risk_level,mitigations):







table=Table(show_header=True,header_style="bold cyan",box=box.ROUNDED)



table.add_column("Parameter",style="bold")



table.add_column("Value")







table.add_row("Name",Text(attack_name,style="bold yellow"))



table.add_row("Description",description)











risk_colors={



"Low":"green",



"Medium":"yellow",



"High":"red",



"Critical":"bold red"



}



risk_color=risk_colors.get(risk_level,"white")







table.add_row("Risk Level",Text(risk_level,style=risk_color))



table.add_row("Mitigations",Text("\n".join([f"- {m}"form in mitigations])))







self.console.pr in t(Panel(table,title="Attack Information",border_style="cyan"))







defshow_techniques(self,techniques):







table=Table(show_header=True,header_style="bold cyan",box=box.ROUNDED)



table.add_column("ID",style="bold cyan",justif y="center")



table.add_column("Name",style="bold yellow")



table.add_column("Category",style="green")



table.add_column("Complexity",style="magenta")



table.add_column("Detection",style="red")







fori,technique in enumerate(techniques,1):



            table.add_row(



str(i),



technique["name"],



technique["category"],



technique["complexity"],



technique["detection"]



)







self.console.pr in t(Panel(table,title="Available Attack Techniques",border_style="cyan"))







defanimate_process in g(self,message,duration=3):







withProgress(



TextColumn("[bold blue]{tas k.description}"),



BarColumn(complete_style="green",f in ished_style="bold green"),



TextColumn("[bold]{tas k.percentage:.0f}%"),



expand=True



)as progress:



            tas k=progress.add_tas k(message,total=100)







fori in range(100):



                time.sleep(duration/100)



progress.update(tas k,advance=1)







deflayout_das hboard(self,sections):







layout=Layout()











if len(sections)<=2:



            layout.split_column(*[Panel(s["content"],title=s["title"],border_style=s.get("style","blue"))fors in sections])



else:



            main_layout=Layout()



main_layout.split_column(*[Panel(s["content"],title=s["title"],border_style=s.get("style","blue"))fors in sections[:2]])







sub_layout=Layout()



sub_layout.split_row(*[Panel(s["content"],title=s["title"],border_style=s.get("style","blue"))fors in sections[2:]])







layout.split_column(main_layout,sub_layout)







self.console.pr in t(layout)







defclear(self):







os.system('cls'if os.name=='nt'else'clear')
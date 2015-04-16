Handleiding voor het gebruik van het portscanscript


D O E L

Middels dit script kunnen de voornaamste poorten gecheckt worden wanneer een nieuwe DC opgeleverd wordt. Het script test:
-een vaste lijst met poorten voor management, waaronder WSUS en SCOM
-een vaste lijst met poorten voor alle systemen waar het domein van het systeem (bijv. prod.ns.nl) en het forest (bijv. fr.ns.nl) trusts mee hebben. Hiermee dient het systeem immers te kunnen communiceren.


B E N O D I G D

-powershel versie 2.0 of hoger. (start powershell middels run>powershell en controleer de major version middels "$host.version"
-script, op moment van schrijven is dat get-jkportscan-v1.71.ps1
-de execuable portqry.exe in dezelfde directory als het script

Indien de execution policy van powershell zeer restrictief staat, moeten het script en de executable staan onder "mijn documenten" in het profiel van de uitvoerder van het script.


U I T V O E R I N G

-Open powershell en navigeer middels cd.. etc naar de directory waar het script en de executable staan.

-Om de uitkomst in een CSV te krijgen ipv enkel op het scherm, moet de uitkomst van het script gepiped worden naar de export-csv functie. Dit gaat door het volgende commando:
	
	Set-ExecutionPolicy -ExecutionPolicy UnRestricted

	.\get-jkportscan.ps1 | export-csv .\portqry-NS01DC042-20150304-112100.csv -NoTypeInformation -Delimiter ';'

De laatste switch -delimiter is gedaan zodat er eenvoudig in excel gesplitst kan worden. Zo herkent excel de kolommen. Het bestand wordt in de werkdirectory aangemaakt.

-Tijdens de uitvoering wordt de voortgang laten zien. Na afloop staat de CSV met de gekozen naam in de werkdirectory. Van hieruit kan deze naar excel gebracht worden.

In excel, kopieer de tekst in. Het kan nodig zijn om nog te splitsen op het karakter ; , als excel dat niet zelf doet. Ga dan naar het tabblad gegevens en kies "tekst naar kolommen">gescheiden>puntkomma>voltooien.

In de laatste kolom kan je een filter plaatsen. Er zijn twee opties. Listening of Filtered. Alle filtered zou opgelost moeten worden.

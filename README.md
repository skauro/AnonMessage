# Crackify
 Anonüümne suhtlusrakendus

## Description
Anonüümne suhtlusrakendus mida saab kasutada samas võrgus suhtlemiseks anonüümselt.

## Installation
Kui juba ei ole laetud alla linuxi põhi teeke ja faile siis tuleb kasutada käsku “sudo apt install build-essential” ja “sudo apt update”.
Seejärel tuleb installida openssl teek käsuga : “sudo apt install openssl”.
Veel tuleb kontrollida versiooni käsuga “openssl version”, kui versioon pole vähemalt 3.0.8 siis tuleb seda ka värskendada.
Lisaks tuleb teek ka pärast konfigureerida sisse süsteemi, et kompilaator teaks kust seda leida. Selle jaoks on juhendeid internetis palju nii, et siin ei hakka täpselt kirjutama.
kui muud openssl teegi osad on laetud tuleb lisaks laadida veel arendaja pakett, mida saab käsuga : “sudo apt-get install libssl-dev”


## Usage
Kliendi programmi kasutamiseks tuleb käivitada kood ja sisestada käsureale kaks parameetrit - serveri port ja IP-aadress. Seejärel küsitakse kasutajalt nime, millega teda terve vestluse ajal kutsutakse.

Serveri programmi käivitamiseks küsitakse porti mille peal kuulatakse ja serveri ipd, sest hetkel pole meil static ip.
 Kui programm käib oodatakse terve aeg ühendusi selle port numbri peal. Kui tekib uus ühendus antakse sellest teada

## loodud 2022
@markni @korgus @janlep

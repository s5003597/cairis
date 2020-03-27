from stix2 import CustomObject, properties
from stix2 import MemoryStore, Filter
from stix2 import parse

from xml.etree.ElementTree import Element, SubElement, ElementTree
from xml.etree.ElementTree import tostring

import requests

def stix_to_iris(inputFile):
    # Parses to SIX Objects and Stores in Memory
    mem = MemoryStore(parse(inputFile, allow_custom=True))

    # Starts XML Document
    risk_analysis = Element('riskanalysis')

    # Builds IRIS XML from STIX Objects
    build_attacker(mem, risk_analysis)
    build_threat(mem, risk_analysis)
    vuln_rels = build_vuln(mem, risk_analysis)
    build_risk(mem, risk_analysis, vuln_rels)

    # Returns as string (file_contents)
    return tostring(risk_analysis)

def build_attacker(mem, risk_analysis):
    available = False
    for threat_actor in mem.query([Filter("type","=", "threat-actor")]):
        xml = SubElement(risk_analysis, 'attacker')

        name = threat_actor["name"]
        # If Identity of threat actor is known, there will be an SRO.
        # E.G Threat Actor SuperHard real name is Mei Qiang
        for sdo in mem.related_to(threat_actor):
            if sdo["type"] == "identity":
                name = sdo["name"]

        xml.set('name', name)
        xml.set('image', '')

        threat_actor_keys = threat_actor.keys()
        
        if "labels" in threat_actor_keys:
            for label in threat_actor["labels"]:
                tag = SubElement(xml, "tag")
                tag.set("name", label)

        if 'description' in threat_actor_keys:
            desc = SubElement(xml, 'description')
            desc.text = threat_actor['description']
        
        env = SubElement(xml, 'attacker_environment')
        env.set('name', 'Default')

        if 'roles' in threat_actor_keys:
            for role in threat_actor['roles']:
                # Creates IRIS Role
                xml = SubElement(risk_analysis, 'role')
                xml.set('name', role)
                xml.set('type', 'Attacker')
                xml.set('short_code', short_code_gen(role.split('-')))
                #desc = SubElement(xml, 'description')
                #desc.text = 'None'

                # Assigns Attacker the Role
                attacker_role = SubElement(env, 'attacker_role')
                attacker_role.set('name', role)
        

        motivations = []
        # Primary Motivations returns a string
        if 'primary_motivation' in threat_actor_keys:
            motivations.append(threat_actor['primary_motivation'])
        # Secondary motivations returns a list of strings
        if 'secondary_motivations' in threat_actor_keys:
            motivations.append(threat_actor['secondary_motivations'])
        for motiv in motivation_format(motivations):
            motivation = SubElement(env, 'motivation')
            motivation.set('name', motiv)
        
        capabilities = []
        if 'resource_level' in threat_actor_keys:
            # Resources/Equipment, Resources/Facilities, Resources/Funding
            # Resources/Personnel and Time
            if 'inidivdual' == threat_actor['resource_level'] or 'club' == threat_actor['resource_level']:
                capabilities.extend([
                    ('Resources/Equipment', 'Low'),
                    ('Resources/Facilities', 'Low'),
                    ('Resources/Funding', 'Low'),
                ])
            elif 'contest' == threat_actor['resource_level'] or 'team' == threat_actor['resource_level']:
                capabilities.extend([
                    ('Resources/Equipment', 'Medium'),
                    ('Resources/Facilities', 'Medium'),
                    ('Resources/Funding', 'Medium'),
                ])
            elif 'organization' == threat_actor['resource_level'] or 'government' == threat_actor['resource_level']:
                capabilities.extend([
                    ('Resources/Equipment', 'High'),
                    ('Resources/Facilities', 'High'),
                    ('Resources/Funding', 'High'),
                ])
        
        if 'sophitication' in threat_actor_keys:
            # Knowledge/Books and Manuals, Education and Training
            # Software, Technology
            if 'minimal' == threat_actor['sophistication']:
                capabilities.extend([
                    ('Knowledge/Education and Training', 'Low'),
                    ('Software', 'Low'),
                    ('Technology', 'Low'),
                ])
            if 'intermediate' == threat_actor['sohpistication']:
                capabilities.extend([
                    ('Knowledge/Education and Training', 'Medium'),
                    ('Knowledge/Books and Manuals', 'Medium'),
                    ('Software', 'Low'),
                ])
            if 'advanced' == threat_actor['sophistication'] or 'expert' == threat_actor['sohpistication']:
                capabilities.extend([
                    ('Knowledge/Education and Training', 'High'),
                    ('Knowledge/Books and Manuals', 'High'),
                    ('Software', 'Medium'),
                    ('Technology', 'Medium')
                ])
            if 'innovator' == threat_actor['sophistication'] or 'strategic' == threat_actor['sophistication']:
                capabilities.extend([
                    ('Knowledge/Education and Training', 'High'),
                    ('Knowledge/Books and Manuals', 'High'),
                    ('Software', 'High'),
                    ('Technology', 'High')
                ])
        
        for capability in capabilities:
            cap = SubElement(env, 'capability')
            cap.set('name', capability[0])
            cap.set('value', capability[1])
        available = True
    
    if not available:
        # Not all risks have known threat actors, when a threat is carried out without known
        # threat actors, they are linked to campaigns. E.g poisonivy.json
        # Campaign represents a group of unknown threat actors
        build_from_campaign(mem, risk_analysis)
        
def build_from_campaign(mem, risk_analysis):
    # Campaign has limited property values, since it represents a group of
    # threat actors, a default campaign role will be set.
    xml = SubElement(risk_analysis, "role")
    xml.set("name", "Campaign")
    xml.set("type", "Attacker")
    xml.set("short_code", "CMPGN")
    for campaign in mem.query([Filter("type","=", "campaign")]):
        xml = SubElement(risk_analysis, 'attacker')
        xml.set("name", campaign["name"])
        xml.set("image", "")

        if "aliaes" in campaign.keys():
            for alias in campaign['aliases']:
                tag = SubElement(xml, "tag")
                tag.set("name", alias)
        
        if "description" in campaign.keys():
            desc = SubElement(xml, "description")
            desc.text = campaign["description"]
        
        env = SubElement(xml, "attacker_environment")
        env.set("name", "Default")
        role = SubElement(env, "attacker_role")
        role.set("name", "Campaign")

    # No Motivation
    # No Capability

def build_threat(mem, risk_analysis):
    # Patterns, malware and tools all can represent as a threat
    attack_patterns = mem.query([Filter("type",  "=", "attack-pattern")])
    malwares = mem.query([Filter("type", "=", "malware")])
    tools = mem.query([Filter("type", "=", "tool")])

    # Loops through each SDO collected
    for threat in (attack_patterns + malwares + tools):
        xml = SubElement(risk_analysis, "threat")
        xml.set("name", threat['name'])

        threat_keys = threat.keys()

        desc = ""
        # Sets the Method if Present
        if 'description' in threat_keys:
            method = SubElement(xml, "method")
            method.text = threat['description']

            # Use desc to certain detect threat type
            desc = threat["description"].lower()
        
        # Sets type of threat based on type or description
        if threat['type'] == 'malware':
            xml.set("type", "Electronic/Malware")
        elif "phish" in desc or "spoof" in desc:
            xml.set("type", "Electronic/Phishing and Spoofing")
        elif "insider" in desc and "manipulat" in desc:
            xml.set("type", "Insider/Manipulation")
        elif "insider" in desc and ("sabotage" in desc or "revenge" in desc):
            xml.set("type", "Insider/Sabotage")
        else:
            xml.set("type", "Electronic/Hacking")
        
        # Sets Labels/Tags if Present
        # Not a requirement
        if 'labels' in threat_keys:
            for label in threat['labels']:
                tag = SubElement(xml, "tag")
                tag.set("name", label)
        
        env = SubElement(xml, "threat_environment")
        env.set("name", "Default")
        #likelihood = input("Likelihood: ")
        likelihood = "Remote"
        env.set("likelihood", likelihood)

        # Checks for attackers that has a direct SRO
        for sdo in mem.related_to(threat):
            if "threat-actor" == sdo["type"] or "campaign" == sdo["type"]:
                attacker = SubElement(env, "threat_attacker")
                attacker.set("name", sdo["name"])


    # No Threatened Assets
    # No Threatened Property
    # Importing into CAIRIS still successful

def build_vuln(mem, risk_analysis):
    vuln_rels = []
    for vuln in mem.query([Filter("type", "=", "vulnerability")]):
        xml = SubElement(risk_analysis, "vulnerability")
        xml.set("name", vuln["name"])

        vuln_keys = vuln_keys()

        if "description" in vuln_keys:
            desc = SubElement(xml, "description")
            desc.text = vuln["description"]

        
        if "external_references" in vuln_keys:
            cve = ""
            # Applies CVE IDs to IRIS Tags
            for ext_ref in vuln["external_references"]:
                tag = SubElement(xml, "tag")
                tag.set("name", ext_ref["external_id"])
                
                if not cve:
                    if ext_ref["source_name"] == "cve":
                        cve = ext_ref["external_id"]
            
            # Builds IRIS vulnerability based on CVE Info
            build_from_cve(cve, xml)
        else:
            print()
            # Build from user input
            # 1. Type
            # 2. Severity
            # 3. Asset
        
        # Checks for any vulnerabilities that have SROs with threats
        # Used when building risks
        for sdo in mem.related_to(vuln):
            if sdo["type"] == "attack-pattern" or sdo["type"] == "malware" or sdo["type"] == "tool":
                vuln_rels.append((vuln, sdo))
    return vuln_rels

def build_from_cve(cve, xml):
    # API (CERT Luxembourg)
    cve_data = requests.get(f"http://cve.circl.lu/api/cve/{cve}").json()

    # Gets type of Vuln, if possible
    vuln_type = ""
    if "capec" in cve_data.keys():
        if cve_data["capec"]:
            if "config" in cve_data["capec"][0]["solutions"].lower():
                vuln_type = "Configuration"
            elif "design" in cve_data["capec"][0]["solutions"].lower():
                vuln_type = "Design"
            elif "implement" in cve_data["capec"][0]["solutions"].lower():
                vuln_type = "Implementation"
    if not vuln_type:
        #vuln_type = input("Type of Vulnerability: ")
        vuln_type = "Design"
    xml.set("type", vuln_type)

    env = SubElement(xml, "vulnerability_environment")
    env.set("name", "Default")

    # Gets severity from cvss score, used NIST guidelines
    if cve_data:
        severity = "Negligible"
        print("cvss")
        if cve_data["cvss"] >= 9:
            severity = "Catastrophic"
        elif cve_data["cvss"] >= 7:
            severity = "Critical"
        elif cve_data["cvss"] >= 4:
            severity = "Marginal"
        env.set("severity", severity)


    # Can retrive list of vulnerable assets affected by CVE.
    # Not being used
    # Checks if 'oval' exists and is not empty
    if "oval" in cve_data.keys() and cve_data["oval"]:
        if "definition_extensions" in cve_data["oval"][0].keys():
            affect_assets = []
            for ext_def in cve_data["oval"][0]["definition_extensions"]:
                product = ext_def["comment"].split(" ")
                asset = ""
                for x in range(0, len(product)):
                    # Checks for version numbers
                    # This is done to reduce flooding asset section of same vulnerable assets
                    if containsNumber(product[x]):
                        # Checks if asset is already known
                        if asset not in affect_assets:
                            affect_assets.append(asset)
                        asset = ""
                        break
                    if asset:
                        asset += " " + product[x]
                        continue
                    asset += product[x]

def build_risk(mem, risk_analysis, vuln_rels):
    # Builds risk from known threats and vuln with SROs
    count = 0
    for vuln, threat in vuln_rels:
        count += 1
        xml = SubElement(risk_analysis, "risk")
        # input() risk name
        xml.set("name", "Risk" + str(count))
        xml.set("vulnerability", vuln["name"])
        xml.set("threat", threat["name"])

        env = SubElement(xml, "misusecase")
        env.set("environment", "Default")
        narrative = SubElement(env, "narrative")
        narrative.text = "Uses " + threat["name"] + " to exploit " + vuln["name"] + "."
             
def containsNumber(inputString):
    # Checks if a number is in a string
    return any(char.isdigit() for char in inputString)

def short_code_gen(words):
    # Generates short code by taking first 3 letters
    short_code = ""
    for word in words:
        short_code += word[0:3].capitalize()
    return short_code

def motivation_format(motivations):
    # Converts STIX Terms into IRIS terms
    # Defined by STIX core documentation
    motivation_terms = {
        'accidental'            :'Accident',
        'coercion'              : 'Cyber-extortion',
        'ideology'              :'Hacktivism',
        'notoriety'             :'Headlines/press',
        'dominance'             :'Improved esteem',
        'organizational-gain'   :'Improved organisational position',
        'unpredictable'         :'Indifference',
        'personal-gain'         :'Money',
        'revenge'               :'Revenge',
        'personal-satisfaction' :'Thrill-seeking',
    }

    # Formats motivations
    motivs = []
    for motivation in motivations:
        if motivation in motivation_terms.keys():
            motivs.append(motivation_terms[motivation])
        else:
            motivs.append(motivation)
    return motivs
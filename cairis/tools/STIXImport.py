from stix2 import MemoryStore, Filter
from stix2 import parse

from xml.etree.ElementTree import Element, SubElement
import xml.etree.ElementTree as ET

s = '<?xml version="1.0"?>\n' +\
    '<!DOCTYPE cairis_model PUBLIC "-//CAIRIS//DTD MODEL 1.0//EN" ' +\
    '"http://cairis.org/dtd/cairis_model.dtd">'


def stix_to_iris(inputFile):
    # Parses to SIX Objects and Stores in Memory
    mem = MemoryStore(parse(inputFile, allow_custom=True))

    cairis_model = Element('cairis_model')

    build_tvtypes(cairis_model)

    cairis = SubElement(cairis_model, 'cairis')
    env = SubElement(cairis, 'environment')
    env.set('name', 'Default')
    env.set('short_code', 'DEF')
    defin = SubElement(env, 'definition')
    defin.text = 'Default environment'

    risk_analysis = SubElement(cairis_model, 'riskanalysis')

    # Builds IRIS XML from STIX Objects
    build_assets(mem, risk_analysis)
    build_attacker(mem, risk_analysis)
    build_threat(mem, risk_analysis)
    vuln_rels = build_vuln(mem, risk_analysis)
    build_risk(mem, risk_analysis, vuln_rels)

    # build_associations(cairis_model, associations)

    return s + ET.tostring(cairis_model).decode('utf-8')


def build_assets(mem, risk_analysis):
    for asset in mem.query([Filter("type", "=", "x-asset")]):
        xml = SubElement(risk_analysis, 'asset')
        xml.set('name', asset['name'])
        xml.set('short_code', short_code_gen([asset['name']]))
        xml.set('type', asset['asset_type'])
        xml.set('is_critical', '0')

        desc = SubElement(xml, 'description')
        desc.text = asset['description']

        sign = SubElement(xml, 'significance')
        sign.text = asset['significance']

        _ = SubElement(xml, 'critical_rationale')

        for prop in asset['impact'].keys():
            value = None
            if asset['impact'][prop][0] == 0:
                continue
            elif asset['impact'][prop][0] == 1:
                value = 'Low'
            elif asset['impact'][prop][0] == 2:
                value = 'Medium'
            elif asset['impact'][prop][0] == 3:
                value = 'High'

            sec_prop = SubElement(xml, 'security_property')
            sec_prop.set('environment', 'Default')
            sec_prop.set('property', prop)
            sec_prop.set('value', value)

            rationale = SubElement(sec_prop, 'rationale')
            rationale.text = asset['impact'][prop][1]


def build_attacker(mem, risk_analysis):
    available = False
    for threat_actor in mem.query([Filter("type", "=", "threat-actor")]):
        xml = SubElement(risk_analysis, 'attacker')

        name = threat_actor["name"]

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
                role_attrib = role.rsplit('-', 1)
                rtypes = ['Attacker', 'Stakeholder', 'Data Subject',
                          'Data Processor', 'Data Controller']
                rattacker = None
                if len(role_attrib) > 1 and role_attrib[-1] in rtypes:
                    rattacker = role_attrib[0]
                    xml.set('name', rattacker.replace('-', ' '))
                    xml.set('type', role_attrib[-1])
                    xml.set('short_code',
                            short_code_gen(role_attrib[0].split('-')))
                else:
                    rattacker = role
                    xml.set('name', rattacker.replace('-', ' '))
                    xml.set('type', 'Attacker')
                    xml.set('short_code', short_code_gen(role.split('-')))

                # Assigns Attacker the Role
                attacker_role = SubElement(env, 'attacker_role')
                attacker_role.set('name', rattacker.replace('-', ' '))
        motivations = None
        # Primary Motivations returns a string
        if 'primary_motivation' in threat_actor_keys:
            motivations = [threat_actor['primary_motivation']]
        # Secondary motivations returns a list of strings
        if 'secondary_motivations' in threat_actor_keys:
            motivations.extend(threat_actor['secondary_motivations'])
        for motiv in motivation_format(motivations):
            motivation = SubElement(env, 'motivation')
            motivation.set('name', motiv)

        capabilities = []
        if 'resource_level' in threat_actor_keys:
            # Resources/Equipment, Resources/Facilities, Resources/Funding
            # Resources/Personnel and Time
            if 'inidivdual' == threat_actor['resource_level'] or\
               'club' == threat_actor['resource_level']:
                capabilities.extend([
                    ('Resources/Equipment', 'Low'),
                    ('Resources/Facilities', 'Low'),
                    ('Resources/Funding', 'Low'),
                ])
            elif 'contest' == threat_actor['resource_level'] or\
                 'team' == threat_actor['resource_level']:
                capabilities.extend([
                    ('Resources/Equipment', 'Medium'),
                    ('Resources/Facilities', 'Medium'),
                    ('Resources/Funding', 'Medium'),
                ])
            elif 'organization' == threat_actor['resource_level'] or\
                 'government' == threat_actor['resource_level']:
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
            if 'advanced' == threat_actor['sophistication'] or\
               'expert' == threat_actor['sohpistication']:
                capabilities.extend([
                    ('Knowledge/Education and Training', 'High'),
                    ('Knowledge/Books and Manuals', 'High'),
                    ('Software', 'Medium'),
                    ('Technology', 'Medium')
                ])
            if 'innovator' == threat_actor['sophistication'] or\
               'strategic' == threat_actor['sophistication']:
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
        # Not all risks have known threat actors,
        # when a threat is carried out without known
        # threat actors, they are linked to campaigns. E.g poisonivy.json
        # Campaign represents a group of unknown threat actors
        build_from_campaign(mem, risk_analysis)


def build_from_campaign(mem, risk_analysis):
    # Campaign has limited property values, since it represents a group of
    # threat actors, a default campaign role will be set.
    for campaign in mem.query([Filter("type", "=", "campaign")]):
        intrusion = False
        role_names = []
        for sdo in mem.related_to(campaign):
            if sdo['type'] == 'intrusion-set':
                xml = SubElement(risk_analysis, 'role')
                xml.set('name', sdo['name'])
                xml.set('type', 'Attacker')
                xml.set('short_code', short_code_gen(sdo['name']))
                if 'description' in sdo.keys():
                    xml.set('description', sdo['description'])
                role_names.append(sdo['name'])
                intrusion = True

        if intrusion:
            xml = SubElement(risk_analysis, "role")
            xml.set("name", "Campaign")
            xml.set("type", "Attacker")
            xml.set("short_code", "CMPGN")
            role_names.append('Campaign')

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
        for name in role_names:
            role = SubElement(env, "attacker_role")
            role.set("name", name)

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
            if len(threat['description']) < 400:
                method.text = threat['description']
            else:
                method.text = threat['description'].splitlines()[0]

            # Use desc to certain detect threat type
            desc = threat["description"].lower()

        # Sets type of threat based on type or description
        if threat['type'] == 'malware':
            xml.set("type", "Electronic/Malware")
        elif threat['type'] == 'tool':
            xml.set('type', 'Electronic/Tool')
        elif 'phish' in desc or 'spoof' in desc:
            xml.set('type', 'Electronic/Phishing and Spoofing')
        elif 'manipulat' in desc:
            xml.set('type', 'Insider/Manipulation')
        elif 'sabotage' in desc or 'revenge' in desc:
            xml.set('type', 'Insider/Sabotage')
        else:
            xml.set('type', 'Electronic/Hacking')

        # Sets Labels/Tags if Present
        # Not a requirement
        if 'labels' in threat_keys:
            for label in threat['labels']:
                tag = SubElement(xml, "tag")
                tag.set("name", label)

        env = SubElement(xml, "threat_environment")
        env.set("name", "Default")

        if 'x_likelihood' in threat_keys:
            env.set('likelihood', threat['x_likelihood'])
        else:
            env.set("likelihood", 'Unknown')

        if 'x_impacts' in threat_keys:
            for prop in threat['x_impacts']:
                value = None
                if threat['x_impacts'][prop][0] == 0:
                    continue
                elif threat['x_impacts'][prop][0] == 1:
                    value = 'Low'
                elif threat['x_impacts'][prop][0] == 2:
                    value = 'Medium'
                elif threat['x_impacts'][prop][0] == 3:
                    value = 'High'

                impact = SubElement(env, 'threatened_property')
                impact.set('name', prop)
                impact.set('value', value)
                rationale = SubElement(impact, 'rationale')
                rationale.text = threat['x_impacts'][prop][1]

        # Checks for attackers that has a direct SRO
        for sdo in mem.related_to(threat):
            if "threat-actor" == sdo["type"] or "campaign" == sdo["type"]:
                attacker = SubElement(env, "threat_attacker")
                attacker.set("name", sdo["name"])

            if sdo['type'] == 'x-asset':
                asset = SubElement(env, 'threatened_asset')
                asset.set('name', sdo['name'])

    # No Threatened Property
    # Importing into CAIRIS still successful


def build_vuln(mem, risk_analysis):
    vuln_rels = []
    for vuln in mem.query([Filter("type", "=", "vulnerability")]):
        xml = SubElement(risk_analysis, "vulnerability")
        xml.set("name", vuln["name"])

        vuln_keys = vuln.keys()

        if 'x_type' in vuln_keys:
            xml.set('type', vuln['x_type'])
        else:
            xml.set('type', 'Unspecified')

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
        env = None
        if 'x_severity' in vuln_keys:
            env = SubElement(xml, 'vulnerability_environment')
            env.set('name', 'Default')
            env.set('severity', vuln['x_severity'])

            # Build from user input
            # 1. Type - Custom Done
            # 2. Severity - Custom Don

        # Checks for any vulnerabilities that have SROs with threats
        # Used when building risks
        for sdo in mem.related_to(vuln):
            if sdo["type"] == "attack-pattern" or\
               sdo["type"] == "malware" or\
               sdo["type"] == "tool":
                vuln_rels.append((vuln, sdo))

            if sdo['type'] == 'x-asset':
                asset = SubElement(env, 'vulnerable_asset')
                asset.set('name', sdo['name'])
    return vuln_rels


def build_risk(mem, risk_analysis, vuln_rels):
    # Builds risk from known threats and vuln with SROs
    associations = []
    count = 1
    for vuln, threat in vuln_rels:
        xml = SubElement(risk_analysis, "risk")
        xml.set("name", "Risk " + str(count))
        xml.set("vulnerability", vuln["name"])
        xml.set("threat", threat["name"])

        associations.append(("Risk " + str(count), threat['name']))
        count += 1

        env = SubElement(xml, "misusecase")
        env.set("environment", "Default")
        narrative = SubElement(env, "narrative")
        narrative.text = "Uses " + threat["name"] +\
                         " to exploit " + vuln["name"] + "."
    return associations


def build_associations(xml, associations):
    association = SubElement(xml, 'associations')
    for risk, threat in associations:
        manual = SubElement(association, 'manual_association')
        manual.set('from_name', risk)
        manual.set('from_dim', 'risk')
        manual.set('to_name', threat)
        manual.set('to_dim', 'threat')


def build_tvtypes(xml):
    vuln_type = {
        "Configuration": "A vulnerability resulting from an error in the configuration and administration of a system or component.",
        "Design": "A vulnerability inherent in the design or specification of hardware or software whereby even a perfect implementation will result in a vulnerability.",
        "Implementation": "A vulnerability resulting from an error made in implementing software or hardware of a satisfactory design.",
    }
    threat_type = {
        "Electronic/DoS and DDoS": "A Denial-of-Service (DoS) attack involves a malicious attempt to disrupt the operation of a computer system or network that is connected to the Internet.  A Distributed Denial-of-Service (DDoS) attack is a more dangerous evolution of a DoS attack because it utilises a network of compromised zombie computers to mount the attack, so there is no identifiable single source.",
        "Electronic/Hacking": "Hackers want to get into your computer system and use them for their own purposes.  There are many hacking tools available on the internet as well as online communities actively discussing hacking techniques enabling even unskilled hackers to break into unprotected systems.  Hackers have a range of motives; from showing off their technical prowess, to theft of money, credentials or information, to cause damage.",
        "Electronic/Keystoke logging": "Keystroke loggers work by recording the sequence of key-strokes that a user types in.  The more sophisticated versions use filtering mechanisms to only record highly prized information such as email addresses, passwords and credit card number sequences.",
        "Electronic/Tool": "Tools are legitimate software that can be used by threat actors to perform attacks.",
        "Electronic/Malware": "Malware is any program or file that is harmful to a computer, the term covers viruses, worms, Trojan horses, and spyware.  Malware is becoming increasingly sophisticated and can be used to compromise computers to install DOS zombie programs or other malicious programs.",
        "Electronic/Phishing and Spoofing": "Phishing describes a social engineering process designed to trick an organisation's customers into imparting confidential information such as passwords, personal data or banking and financial details.  Most commonly these are criminal attacks but the same techniques could be used by others to get sensitive information.",
        "Insider/Manipulation": "Sometimes deliberate attempts are made to acquire information or access by manipulating staff by using a range of influencing techniques.  This is sometimes described as social engineering, creating situations in which someone will willingly provide access to information, sites or systems to someone unauthorised to receive it.  Customer facing personnel who have been trained to be helpful and informative can be particularly vulnerable to such attacks.",
        "Insider/Sabotage": "Saborage is often committed by a former employee seeking revenge on their employer because of a personal grudge caused by a negative work related event such as dismissal.  Although it is sometimes planned well in advance, it can also be the result of an opportunistic moment.",
        "Natural": "Environment / Acts of Nature",
        "Physical": "Physical Security"
    }
    tvtypes = SubElement(xml, 'tvtypes')
    for key in vuln_type.keys():
        vulntype = SubElement(tvtypes, 'vulnerability_type')
        vulntype.set("name", key)
        desc = SubElement(vulntype, 'description')
        desc.text = vuln_type[key]

    for key in threat_type.keys():
        threattype = SubElement(tvtypes, 'threat_type')
        threattype.set("name", key)
        desc = SubElement(threattype, 'description')
        desc.text = threat_type[key]


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
        'accidental': 'Accident',
        'coercion': 'Cyber-extortion',
        'ideology': 'Hacktivism',
        'notoriety': 'Headlines/press',
        'dominance': 'Improved esteem',
        'organizational-gain': 'Improved organisational position',
        'unpredictable': 'Indifference',
        'personal-gain': 'Money',
        'revenge': 'Revenge',
        'personal-satisfaction': 'Thrill-seeking',
    }

    # Formats motivations
    motivs = []
    for motivation in motivations:
        if motivation in motivation_terms.keys():
            motivs.append(motivation_terms[motivation])
        else:
            motivs.append(motivation)
    return motivs

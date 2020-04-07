from cairis.mio.RiskAnalysisContentHandler import RiskAnalysisContentHandler
from stix2 import MemoryStore, Filter
from stix2 import CustomObject, properties
from stix2 import Vulnerability, Relationship, ThreatActor
from stix2 import AttackPattern, Malware, Tool, Bundle
import xml.sax

PROP_TYPES = ['confidentiality', 'integrity', 'availability', 'accountability',
              'anonmity', 'pseudonymity', 'unlinkability', 'unobservability']


@CustomObject('x-asset', [
    ('name', properties.StringProperty(required=True)),
    ('description', properties.StringProperty(required=True)),
    ('asset_type', properties.StringProperty(required=True)),
    ('significance', properties.StringProperty(required=True)),
    ('impact', properties.DictionaryProperty(required=True)),
    ('labels', properties.ListProperty(contained=str)),
])
class Asset(object):
    def __init__(self, asset_type=None, impact=None, **kwargs):
        if asset_type and asset_type not in ['Hardware', 'Information',
                                             'People', 'Software',
                                             'System of Systems', 'Systems',
                                             'Systems - General']:
            raise ValueError(f"'{asset_type}'' is not a valid asset type.")
        if impact:
            for item in impact.items():
                if item[0] not in PROP_TYPES:
                    raise ValueError("'{item[0]}' is not a valid impact type.")
                if item[1][0] not in [0, 1, 2, 3]:
                    raise ValueError("'{item[1][0]}' is not a valid value.")


def iris_to_stix(inputFile):
    handler = RiskAnalysisContentHandler()
    xml.sax.parseString(inputFile, handler)
    mem = MemoryStore()

    build_assets(handler.assets(), mem)
    build_vulns(handler.vulnerabilities(), mem)
    build_threatactors(handler.attackers(), handler.roles(), mem)
    build_threats(handler.threats(), mem)
    build_risks(handler.risks(), mem)

    all_objs = Bundle(mem.query())

    return all_objs.serialize(encoding='utf-8')


def build_assets(assets, mem):
    for asset in assets:
        for envprop in asset.environmentProperties():
            values = envprop.properties()
            rationale = envprop.rationale()
            pairs = [(values[i], rationale[i]) for i in range(0, len(values))]
            impacts = {PROP_TYPES[i]: pairs[i] for i in range(len(PROP_TYPES))}

            mem.add(Asset(
                    name=asset.name(),
                    description=asset.description(),
                    asset_type=asset.type(),
                    significance=asset.significance(),
                    impact=impacts,
                    labels=asset.tags()))


def build_vulns(vulns, mem):
    for vuln in vulns:
        # Gets CVE From Tags if present
        external_ref = []
        if vuln.tags():
            for tag in vulns.tags():
                if tag.startswith('CVE-'):
                    external_ref.append({
                        'source_name': 'cve',
                        'external_id': tag})
                    break

        stix_vuln = Vulnerability(
                name=vuln.name(),
                description=vuln.description(),
                external_references=external_ref,
                custom_properties={
                    'x_type': vuln.type(),
                    'x_severity': vuln.environmentProperties()[0].severity()
                }
            )
        mem.add(stix_vuln)

        for envprop in vuln.environmentProperties():
            for asset in envprop.assets():
                for sdo in mem.query([Filter("type", "=", "x-asset")]):
                    if asset == sdo['name']:
                        mem.add(Relationship(
                            relationship_type='targets',
                            source_ref=stix_vuln,
                            target_ref=sdo))


def build_threatactors(attackers, risk_roles, mem):
    for attacker in attackers:
        labels, motives, roles, capabilities = [], [], [], []
        for envprop in attacker.environmentProperties():
            # Gets motives, tries to use STIX Vocab
            motives = format_motives(envprop.motives())
            # Infer labels from motivations
            labels = infer_threat_labels(motives) + attacker.tags()
            # Gets list of role names
            attacker_roles = envprop.roles()
            roles = []
            for role in risk_roles:
                if role.name() in attacker_roles:
                    roles.append(role.name().replace(' ', '-') +
                                 '-' + role.type())
            # Gets Capabilities
            resource_count, soph_count = 0, 0
            for (name, value) in envprop.capabilities():
                if name.startswith('Resource/'):
                    if value == 'High':
                        resource_count += 1
                    elif value == 'Low':
                        resource_count -= 1
                else:
                    if value == 'High':
                        soph_count += 1
                    elif value == 'Low':
                        soph_count -= 1
            # Checks count to determine levels
            if resource_count >= 2:
                capabilities.append('government')
            elif resource_count >= 1:
                capabilities.append('content')
            else:
                capabilities.append('inidivdual')

            if soph_count >= 2:
                capabilities.append('advanced')
            elif soph_count >= 1:
                capabilities.append('intermediate')
            else:
                capabilities.append('minimal')

        mem.add(ThreatActor(
                name=attacker.name(),
                description=attacker.description(),
                labels=labels,
                roles=roles,
                resource_level=capabilities[0],
                sophistication=capabilities[1],
                primary_motivation=motives[0],
                secondary_motivations=motives[1:]))


def build_threats(threats, mem):
    for threat in threats:
        custom_properties = {
            'x_likelihood': threat.environmentProperties()[0].likelihood(),
        }

        assets, attackers = [], []
        for envprop in threat.environmentProperties():
            values = envprop.properties()
            rationale = envprop.rationale()
            pairs = [(values[i], rationale[i]) for i in range(0, len(values))]
            impacts = {PROP_TYPES[i]: pairs[i] for i in range(len(PROP_TYPES))}
            custom_properties['x_impacts'] = impacts

            assets.extend(envprop.assets())
            attackers.extend(envprop.attackers())

        threat_sdo = None
        if threat.type() == 'Electronic/Malware' or\
           threat.type() == 'Electronic/DoS and DDoS' or\
           threat.type() == 'Electronic/Keystoke Logging':

            labels = threat.tags() if threat.tags() else malware_labels(threat)
            threat_sdo = Malware(
                name=threat.name(),
                description=threat.method(),
                labels=labels,
                custom_properties=custom_properties,
            )
        elif threat.type() == 'Electronic/Tool':
            labels = threat.tags() if threat.tags() else tool_labels(threat)
            threat_sdo = Tool(
                name=threat.name(),
                description=threat.method(),
                labels=labels,
                custom_properties=custom_properties,
            )
        else:
            external_ref = []
            if threat.tags():
                for tag in threat.tags():
                    if tag.startswith('CAPEC-'):
                        external_ref.append({
                            'source_name': 'capec',
                            'external_id': tag
                        })
            threat_sdo = AttackPattern(
                name=threat.name(),
                description=threat.method(),
                external_references=external_ref,
                custom_properties=custom_properties,
            )

        mem.add(threat_sdo)

        # Creates SRO between Threat & Asset
        asset_sdos = mem.query([Filter("type", "=", "x-asset")])
        for asset in assets:
            for sdo in asset_sdos:
                if asset == sdo['name']:
                    mem.add(Relationship(
                        relationship_type='targets',
                        source_ref=threat_sdo,
                        target_ref=sdo
                    ))

        # Creates SRO between Threat & Attacker
        attacker_sdos = mem.query([Filter("type", "=", "threat-actor")])
        for attacker in attackers:
            for sdo in attacker_sdos:
                if attacker == sdo['name']:
                    mem.add(Relationship(
                        relationship_type='uses',
                        source_ref=sdo,
                        target_ref=threat_sdo
                    ))


def build_risks(risks, mem):
    # Since risks are infered, only SROs are created
    threat_sdos = mem.query([Filter("type", "=", "attack-pattern")]) +\
                  mem.query([Filter("type", "=", "malware")]) +\
                  mem.query([Filter("type", "=", "tool")])
    vuln_sdos = mem.query([Filter("type", "=", "vulnerability")])

    for risk in risks:
        threat = None
        for sdo in threat_sdos:
            if sdo['name'] == risk.threat():
                threat = sdo
        vuln = None
        for sdo in vuln_sdos:
            if sdo['name'] == risk.vulnerability():
                vuln = sdo

        mem.add(Relationship(
            relationship_type='targets',
            source_ref=threat,
            target_ref=vuln
        ))


def tool_labels(threat):
    stix_vocab = [
        'denial-of-service', 'exploitation',
        'information-gather', 'network-capture',
        'credential-exploitation', 'remote-access',
        'vulnerability-scanning',
    ]
    labels = []
    for vocab in stix_vocab:
        if vocab.replace('-', ' ') in threat.metho():
            labels.append(vocab)
    if labels:
        return labels
    return ['tool']


def malware_labels(threat):
    stix_vocab = [
        'adware', 'backdoor', 'bot',
        'dropper', 'exploit-kit', 'ransomware',
        'trojan', 'resource-exploitation',
        'rogue-security-software', 'rootkit', 'screen-capture',
        'spyware', 'virus', 'worm'
    ]
    labels = []
    if threat.type() == 'Electronic/DoS and DDoS':
        labels.append('ddos')
    if threat.type() == 'Electronic/Keystoke Logging':
        labels.append('keylogger')

    for vocab in stix_vocab:
        if vocab.replace('-', ' ') in threat.method():
            labels.append(vocab)
    if labels:
        return labels
    return ['malware']


def format_motives(motives):
    motivation_terms = {
        'Accident': 'accidental',
        'Cyber-extortion': 'coercion',
        'Hacktivism': 'ideology',
        'Headlines/press': 'notoriety',
        'Improved esteem': 'dominance',
        'Improved organisational position': 'organizational-gain',
        'Indifference': 'unpredictable',
        'Money': 'personal-gain',
        'Revenge': 'revenge',
        'Thrill-seeking': 'personal-satisfaction',
    }
    stix_motives = []
    for motive in motives:
        if motive in motivation_terms.keys():
            stix_motives.append(motivation_terms[motive])
            continue
        stix_motives.append(motive)

    return stix_motives


def infer_threat_labels(labels):
    label_terms = {
        'ideology': 'activist',
        'organizational-gain': 'competitor',
        'personal-satisfaction': 'hacker',
        'accidental': 'insider-accidental',
        'revenge': 'insider-disgruntled',
        'notoriety': 'sensationalist',
    }
    stix_labels = ['criminal']
    for label in labels:
        if label in label_terms.keys():
            stix_labels.append(label_terms[label])
            continue
        stix_labels.append(label)

    return stix_labels

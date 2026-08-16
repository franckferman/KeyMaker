"""Vendor name pools for code-signing cert subjects."""

# Enterprise IT / security / integrators — recognisable, low EDR suspicion
ENTERPRISE = [
    "Cisco Systems",
    "Oracle Corporation",
    "Dell Technologies",
    "HP Inc.",
    "Hewlett Packard Enterprise",
    "IBM Corporation",
    "Microsoft Corporation",
    "SAP SE",
    "VMware Inc.",
    "Palo Alto Networks",
    "CrowdStrike Inc.",
    "Fortinet Inc.",
    "Check Point Software Technologies",
    "Symantec Corporation",
    "McAfee LLC",
    "Broadcom Inc.",
    "Juniper Networks",
    "F5 Networks",
    "Citrix Systems",
    "Nutanix Inc.",
]

# Banking / finance sector vendors — relevant for bank RT environments
BANKING = [
    "Thales Group",
    "Capgemini SE",
    "Sopra Steria Group",
    "Accenture PLC",
    "Atos SE",
    "Econocom Group",
    "Inetum SA",
    "CGI Inc.",
    "Infosys Limited",
    "Tata Consultancy Services",
    "Temenos AG",
    "Finastra Limited",
    "FIS Global",
    "Fiserv Inc.",
    "Worldline SA",
    "Ingenico Group",
    "SWIFT SCRL",
    "Murex SAS",
    "Calypso Technology",
    "Vermeg SA",
]

# French / EU tech — for French banking sector engagements
FRENCH = [
    "Dassault Systemes SE",
    "Ubisoft Entertainment",
    "OVH SAS",
    "Criteo SA",
    "Alten SA",
    "ALTEN Group",
    "Aubay SA",
    "Devoteam SA",
    "Wavestone SAS",
    "Onepoint SAS",
    "Berger-Levrault SAS",
    "GFI Informatique",
    "Idemia Group SAS",
    "IN Groupe SAS",
    "Eviden SAS",
]

# Generic "software" / "services" — low-profile
GENERIC = [
    "Synapse Software Ltd",
    "Nexus Data Systems Inc.",
    "Axiom Technologies LLC",
    "CoreSync Solutions Inc.",
    "Meridian Software Group",
    "Vertex Systems Corp.",
    "Apex Digital Services Ltd",
    "Matrix Software Solutions",
    "Prism Analytics Inc.",
    "Quantum Edge Technologies",
    "Helix Data Corp.",
    "Orion Systems Group",
    "Titan Software Ltd",
    "Atlas Technology Solutions",
    "Sigma Computing Inc.",
]

ALL = ENTERPRISE + BANKING + FRENCH + GENERIC

POOLS = {
    "enterprise": ENTERPRISE,
    "banking": BANKING,
    "french": FRENCH,
    "generic": GENERIC,
    "all": ALL,
}

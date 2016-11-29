__author__ = 'apoorva'

import os
import sys
import time
# from os.path import join, abspath, dirname
from pprint import pprint
from datetime import datetime

try:
    # python-stix : Used in initial parsing, only to get stix file as a dictionary
    from stix.core import STIXPackage
    from stix.coa import CourseOfAction
    from cybox.bindings.file_object import FileObjectType
    from cybox.bindings.account_object import AccountObjectType
    from cybox.bindings.email_message_object import EmailHeaderType, EmailMessageObjectType, EmailRecipientsType
    from cybox.bindings.domain_name_object import DomainNameObjectType
    from cybox.bindings.uri_object import URIObjectType
    from cybox.bindings.address_object import AddressObjectType
    from cybox.bindings.network_connection_object import NetworkConnectionObjectType
    from cybox.bindings.mutex_object import MutexObjectType
    from cybox.bindings.link_object import LinkObjectType
    from cybox.bindings.win_registry_key_object import WindowsRegistryKeyObjectType
    from cybox.common.datetimewithprecision import DateTimeWithPrecision

    from stix.utils.parser import UnsupportedVersionError
except ImportError:
    print "Error: Could not import required libraries. Requires python-stix and python-cybox libraries. " \
          "See https://stix.mitre.org/ " \
          "See https://cyboxproject.github.io/"
    sys.exit(-1)

try:
    # Python-Neo4j interface
    from py2neo import Graph, Node, Relationship, authenticate
    from py2neo.database.status import ConstraintError
except ImportError:
    print "Error: Could not import required libraries. Requires py2neo library. See http://py2neo.org/v3/"
    sys.exit(-1)

# logging
import logging

reload(logging)
logging.basicConfig(format=u'[%(asctime)s]  %(message)s', level=logging.INFO)

stixGraph = Graph("http://neo4j:neo4jtest@127.0.0.1:7474/db/data")
stixGraph.delete_all()
#stixGraph.run("DROP CONSTRAINT ON (k:KillChainPhaseNode)ASSERT k.ID IS UNIQUE")

#stixGraph.run("MATCH (n) DETACH DELETE n")
#Init Node
desc = "This Node will connect to LM Kill Chain, all STIX Header,Observable nodes to make sure the graph is not disconnected"
stixGraph.run("CREATE CONSTRAINT ON (n:InitNode) ASSERT n.NodeID IS UNIQUE")
init_node = Node("StixGraph", Description=desc, NodeID="InitNode")
stixGraph.create(init_node)


def test_GreenIOC():
    test_path = '../Green_IOCs/'
    test_data = os.listdir(test_path)

    logging.info('Opening all files in Green_IOCs')

    for fle in test_data:
        try:
            myfile = str(test_path) + str(fle)
            if myfile:
                parse_file(myfile)
        except UnsupportedVersionError, err:
            print "-> Skipping %s\n    UnsupportedVersionError: %s" % (myfile, err)
            print "See https://github.com/STIXProject/python-stix/issues/124"
        except Exception, err:
            print "-> Unexpected error parsing %s: %s; skipping." % (myfile, err)
    logging.info('Closing all files in Green_IOCs')


def test_files():
    # PATH vars
    #here = lambda *x: join(abspath(dirname(__file__)), *x)
    #PROJECT_ROOT = here("..")
    #root = lambda *x: join(abspath(PROJECT_ROOT), *x)
    #sys.path.insert(0, root('TEST'))
    test_path = '../TEST/'
    test_data = os.listdir(test_path)

    logging.info('Opening files in TEST')

    for fle in test_data:
        if not fle.endswith("xml"):
            continue
        myfile = str(test_path) + str(fle)
        if myfile:
            parse_file(myfile)

    '''
        try:
            myfile = str(test_path)+str(fle)
            if myfile:
                parse_file(myfile)
        except Exception, err:
                    print "-> Unexpected error parsing %s: %s; skipping." % (myfile, err)
    '''
    logging.info('Closing files in TEST')


def parse_observables(observables, StixFileID, indicatorID, incidentID):
    #objRelated = {}
    for obs in observables:
        #parse_observable(obs, StixFileID, objRelated, indicatorID, incidentID)
        parse_observable(obs, StixFileID, indicatorID,incidentID)
    '''
    if len(objRelated) != 0 :
        for key, val in objRelated:
            objNode = stixGraph.find_one("ObservableNode", property_key="ObjectID", property_value=key)
            relObjNode = stixGraph.find_one("ObservableNode", property_key="RelatedObjectID", property_value= val)
            if relObjNode and objNode:
                relPhase = Relationship(relObjNode, "RelatedObjectLink", objNode,
                    ObjectID =key, RelatedObjectID = val)
                try:
                    stixGraph.merge(relPhase)
                except ConstraintError:
                    pass
                except AttributeError:
                    pass
    '''
#def parse_observable(obs, StixFileID, objRelated, indicatorID, incidentID):
def parse_observable(obs, StixFileID, indicatorID, incidentID):
    obj = obs.to_obj()
    if not obj or not hasattr(obj, "Object") or not hasattr(obj.Object, "Properties"): return
    prop = obj.Object.Properties

    stixGraph.run("CREATE CONSTRAINT ON (n:ObservableNode) ASSERT n.ObservableID IS UNIQUE")
    ObservableNode = Node("ObservableNode", ObservableID=obs.id_, ObjectID=obj.Object.id,
                          xsiType=prop.xsi_type,STIXFileID=StixFileID)
    if indicatorID: ObservableNode["IndicatorID"]= indicatorID
    if incidentID:
        ObservableNode["IncidentID"]= incidentID

    #print "Observable: " + obs.id_  #Observable ID
    #obj = obs.get('object')
    #print "Related Observable: " + obj.id
    #prop = obs.get('object').get('properties')

    #print "XSI Type: " + prop.xsi_type

    if (type(prop) == FileObjectType):
        try:
            #print "Size(in Bytes) : " + str(prop.Size_In_Bytes.valueOf_)
            ObservableNode["SizeInBytes"] = prop.Size_In_Bytes.valueOf_
        except AttributeError:
            size = 0
        #FileName
        try:
            print prop.category + ": " + prop.Address_Value
            print "File Name: " + obj.File_Name

            ObservableNode["Category"] = prop.category
            ObservableNode["AddressValue"] = prop.Address_Value
            ObservableNode["FileName"] = obj.File_Name
        except AttributeError:
            fileName = None

        if (prop.Hashes != None):
            hashType = prop.Hashes.Hash
            for i, hash in enumerate(hashType):
                h = hash.Type.valueOf_
                if ( h == "MD5" or h == "MD6" or h == "SHA1" or h == "SHA224" or
                             h == "SHA256" or h == "SHA=384" or h == "SHA512"):
                    hashVal = hash.Simple_Hash_Value.valueOf_
                elif ( h == "SSDEEP"):
                    hashVal = hash.Fuzzy_Hash_Value.valueOf_
                else:
                    hashVal = 0  #hash.Fuzzy_Hash_Structure
                    hashType = "Fuzzy Structure"
                #print "Hash(Type : Value) " + str(h) + ":" + str(hashVal)
                if h!= None:
                    ObservableNode[h]=hashVal
    elif (type(prop) == AddressObjectType):
        ObservableNode["Category"] = prop.category
        ObservableNode["AddressValue"] = prop.Address_Value.valueOf_
        ObservableNode["ApplyCondition"] = prop.Address_Value.apply_condition
        ObservableNode["Condition"] = prop.Address_Value.condition

    elif (type(prop) == URIObjectType):

        #Email Header has the following attributes: message_id, from, sender, subject
        emailHeader = prop.Header
        if emailHeader:
            if emailHeader.Message_ID:
                ObservableNode["MessageID"] = emailHeader.Message_ID.valueOf_

            if emailHeader.From:
                #print "\t" + emailHeader.From.category + " (ObjType " + emailHeader.From.xsi_type + ") from " + emailHeader.From.Address_Value.valueOf_

                ObservableNode["From_Category"] = emailHeader.From.category
                ObservableNode["From_xsiType"] = emailHeader.From.xsi_type
                ObservableNode["From_AddressValue"] = emailHeader.From.Address_Value.valueOf_
            if emailHeader.Sender:
                #print "\t" + emailHeader.Sender.category + " (ObjType: " + emailHeader.Sender.xsi_type + ") sent to " + emailHeader.Sender.Address_Value.valueOf_

                ObservableNode["Sender_Category"] = emailHeader.Sender.category
                ObservableNode["Sender_xsiType"] = emailHeader.Sender.xsi_type
                ObservableNode["Sender_AddressValue"] = emailHeader.Sender.Address_Value.valueOf_
            if emailHeader.Subject:
                #print  "\tSubject (Apply condition: condition::delimiter: Value) " + emailHeader.Subject.apply_condition + ":" + emailHeader.Subject.condition + ":" + emailHeader.Subject.delimiter + ":" + ":" + emailHeader.Subject.valueOf_

                ObservableNode["Subject_ApplyCondition"] = emailHeader.Subject.apply_condition
                ObservableNode["Subject_Condition"] = emailHeader.Subject.condition
                ObservableNode["Subject_Delimiter"] = emailHeader.Subject.delimiter
                ObservableNode["Subject_Value"] = emailHeader.Subject.valueOf_

            #Email Attachments
            if prop.Attachments:
                emailAttachments = prop.Attachments.File
                #print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                #print "Email Attachments: "
                for i, attach in enumerate(emailAttachments):
                    #print "\t" + attach.object_reference
                    em = "EmailAttachment#" + str(i)
                    ObservableNode[em] = attach.object_reference

    elif( type(prop) == LinkObjectType):
        if prop.type_ : ObservableNode["Type"] = prop.type_
        if prop.xsi_type: ObservableNode["xsiType"] = prop.xsi_type

        if prop.URL_Label.apply_condition: ObservableNode["Link_ApplyCondition"] = prop.URL_Label.apply_condition
        if prop.URL_Label.pattern_type : ObservableNode["Link_PatternType"] = prop.URL_Label.pattern_type
        if prop.URL_Label.condition : ObservableNode["Link_Condition"] = prop.URL_Label.condition
        if prop.URL_Label.delimiter: ObservableNode["Link_Delimiter"] = prop.URL_Label.delimiter
        if prop.URL_Label.valueOf_ : ObservableNode["Link_Value"] = prop.URL_Label.valueOf_

        if prop.Value.apply_condition: ObservableNode["Link_ApplyCondition"] = prop.Value.apply_condition
        if prop.Value.condition : ObservableNode["Link_Condition"] = prop.Value.condition
        if prop.Value.delimiter: ObservableNode["Link_Delimiter"] = prop.Value.delimiter
        if prop.Value.valueOf_ : ObservableNode["Link_Value"] = prop.Value.valueOf_

    elif ( type(prop) == NetworkConnectionObjectType):
        if prop.Creation_Time:
            ObservableNode["CreationTime"]= str(prop.Creation_Time)
        if prop.Destination_TCP_State:
            ObservableNode["DestinationTCPState"]= str(prop.Destination_TCP_State)
        if prop.Source_TCP_State:
            ObservableNode["SourceTCPState"]= str(prop.Source_TCP_State)
        if prop.Layer3_Protocol:
            ObservableNode["Layer3Protocol"] = str(prop.Layer3_Protocol)
        if prop.Layer4_Protocol:
            ObservableNode["Layer4Protocol"] = str(prop.Layer4_Protocol)
        if prop.Layer7_Protocol:
            ObservableNode["Layer7Protocol"] = str(prop.Layer7_Protocol)
        if prop.Layer7_Connections:
            ObservableNode["Layer7Connections"] = str(prop.Layer7_Connections)
        if prop.Source_Socket_Address:
            ObservableNode["SourceSocketAddress"] = str(prop.Source_Socket_Address)
        # Should be expanded
        if prop.Destination_Socket_Address:
            ObservableNode["DestinationSocketAddress"] = str(prop.Destination_Socket_Address)
        if prop.xsi_type:
            ObservableNode["xsiType"] = prop.xsi_type

    elif ( type(prop)== WindowsRegistryKeyObjectType):
        if prop.Byte_Runs: ObservableNode["ByteRuns"] = prop.Byte_Runs
        if prop.Creator_Username: ObservableNode["CreatorUsername"]= prop.Creator_Username
        if prop.Hive: ObservableNode["HiveValue"] = prop.Hive.valueOf_
        if prop.Key: ObservableNode["KeyValue"] = prop.Key.valueOf_

        for i,val in enumerate(prop.Values.Value):
            vn = "ValueName"+str(i)
            vd = "ValueData"+str(i)
            if val.Data: ObservableNode[vd] = val.Data.valueOf_
            if val.Name:ObservableNode[vn]=val.Name.valueOf_

        if prop.xsi_type: ObservableNode["xsiType"] = prop.xsi_type

        #print "HandleWindowsRegistryKeyObjectType Win Registry Key Object"

    elif (type(prop)== MutexObjectType):
        ObservableNode["xsiType"] = prop.xsi_type
        ObservableNode["MutexValue"]=prop.Name.valueOf_
    else:
        ObservableNode["xsiType"] = prop.xsi_type
        print "Handle "+ prop.xsi_type

    if obj.Object.Related_Objects:
        reltd = obj.Object.Related_Objects.Related_Object
        for i,reltdObj in enumerate(reltd):
            ObservableNode["RelatedObjectID"+str(i)] = reltdObj.id
            #if obj.Object.id and reltdObj.id:
                #objRelated[str(obj.Object.id)] = str(reltdObj.id)
            if (type(reltdObj.Properties) == MutexObjectType):
                '''
                print "Handle Mutex Type Object"
                print " Properties : \n\t"+reltdObj.Properties.Name.apply_condition+"\n\t"
                print reltdObj.Properties.Name.condition+"\n\t"
                print reltdObj.Properties.Name.delimiter+"\n\t"
                print reltdObj.Properties.Name.valueOf_
                '''
                ObservableNode["RelatedObjMutexValue"+str(i)]= str(reltdObj.Properties.Name.valueOf_)
            elif (type(reltdObj.Properties) == FileObjectType):
                #print "Handle File Object"
                ObservableNode["RelatedObjFileName"+str(i)]= reltdObj.Properties.File_Name.valueOf_
                ObservableNode["RelatedObjFileExtension"+str(i)]= reltdObj.Properties.File_Extension.valueOf_
            elif (type(reltdObj.Properties) == AddressObjectType):
                ObservableNode["RelatedObjAddressValue"+str(i)]= str(reltdObj.Properties.Address_Value.valueOf_)
            else:
                print "Related Object to be handled"

    try:
        headNode = stixGraph.find_one("HeaderNode", property_key="STIXFileID", property_value=StixFileID)
        rel = Relationship(headNode, "HeaderObservableLink", ObservableNode, STIXFileID=StixFileID,
                          connect="To make sure graph isn't disconnected")
        stixGraph.merge(rel)
    except AttributeError:
        pass
    '''
    obsNode = stixGraph.find_one("ObservableNode", property_key="ObjectID", property_value=obj.id)
    if obsNode:
        relObs = Relationship(ObservableNode, "ObservableLink", obsNode, RelatedObservableID=obs.id_)
        stixGraph.merge(relObs)

    '''


def parse_header(header, StixFileID):
    print "***********************************************HEADER*********************************************"
    head = header.to_obj()
    HeaderNode = Node("HeaderNode",Title=header.title, Description= str(header.description), STIXFileID=StixFileID)

    #head.Profiles
    #head.Title

    #for desc in head.Description: #(LIST)
    #desc.id
    #desc.idref
    #desc.ordinality
    #desc.structuring_format
    #desc.valueOf_

    #for mark in head.Handling.Marking: #(LIST)
    #mark.Controlled_Structure
    #mark.Information_Source
    #mark.id
    #mark.idref
    #mark.version

    #for struc in mark.Marking_Structure: #(LIST)
    #struc.color
    #struc.id
    #struc.idref
    #struc.marking_model_name
    #struc.marking_model_ref
    #struc.xml_type
    #struc.xmlns
    #struc.xmlns_prefix


    #head.Information_Source.Contributing_Sources
    #head.Information_Source.Identity
    #head.Information_Source.References
    #head.Information_Source.Tools

    #for des in head.Information_Source.Description: #(LIST) ???
    #for role in head.Information_Source.Role: #(LIST) ???

    #head.Information_Source.Time.EndTime
    #head.Information_Source.Time.ReceivedTime
    #head.Information_Source.Time.Start_Time

    #head.Information_Source.Time.Produced_Time #(DatetimeWithPrecisionType)
    #head.Information_Source.Time.Produced_Time.precision
    #head.Information_Source.Time.Produced_Time.valueOf_

    #for pkInt in head.Package_Intent: #(LIST)
    #pkInt.valueOf_
    #pkInt.vocab_name
    #pkInt.vocab_reference
    #pkInt.xsi_type

    #for des in head.Short_Description: #(LIST) ???

    dt = ""
    tm = ""
    for h in head.Description:
        desc = h.valueOf_
        print "Description:\n" + desc + "\n"
    try:
        head_date = head.Information_Source.Time.Produced_Time.valueOf_
    except AttributeError:
        now = datetime.today()
        head_date = str(now.strftime("%Y-%m-%dT%H:%M:%S+00:00"))     #If there is no timestamp, adding today's timestamp..!!

    dt, tm = head_date.split("T", 1)
    year, month, day = dt.split("-", 2)
    tm2, ms = tm.split("+", 1)
    HH, MM, SS = tm2.split(":", 2)

    HeaderNode["ProducedDate"]= dt
    HeaderNode["ProducedTime"] = tm

    months = {"01": 'Jan', "02": 'Feb', "03": 'Mar', "04": 'Apr', "05": 'May', "06": 'Jun', "07": 'Jul',
              "08": 'Aug', "09": 'Sep', "10": 'Oct', "11": 'Nov', "12": 'Dec'}
    print "Produced Date:" + day + " " + str(months.get(month)) + ", " + year
    print "Produced Time(24 HR):" + HH + ":" + MM + ":" + SS

    #+"Produced Time Precision: "+ head.Information_Source.Time.Produced_Time.precision

    for pkInt in head.Package_Intent:
        print "XSI-TYPE: " + pkInt.xsi_type
        HeaderNode["PackageIntent"]=pkInt.valueOf_

    for mark in head.Handling.Marking:
        print "Marking:\n\t Controlled Structure: " + mark.Controlled_Structure
        for struc in mark.Marking_Structure:
            color = struc.color
            HeaderNode["MarkingColor"]= color
            print "\t\tMarking Color: " + color
            #struc.id
            #struc.idref
            #struc.marking_model_name
            #struc.marking_model_ref
            print "\t\t XML-TYPE: " + struc.xml_type
            print "\t\tXML-Namespace: " + struc.xmlns
            print "\t\tXMLNS Prefix: " + struc.xmlns_prefix

    rel = Relationship(init_node, "HeaderGraphLink", HeaderNode, connect="To make sure graph isn't disconnected",
                       STIXFileID=StixFileID)
    stixGraph.merge(rel)


def parse_indicator(indicator, id, kill_chains, kill_chain_phases, StixFileID):
    #print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    keyIndValueList = []

    desc = "Indicators contains threat information and how to handle them within its observables, kill_chain phases etc.Connected to initNode"
    stixGraph.run("CREATE CONSTRAINT ON (n:IndicatorNode) ASSERT n.ID IS UNIQUE")
    IndicatorNode = Node("IndicatorNode", Description=desc, STIXFileID=StixFileID, ID=indicator.id_)
    #rel = Relationship(init_node, "IndicatorGraphLink", IndicatorNode, connect="To make sure graph isn't disconnected",STIXFileID=StixFileID)

    if indicator.confidence: IndicatorNode["Confidence"] = str(indicator.confidence)
    if indicator.handling: IndicatorNode["Handling"] = str(indicator.handling)
    if indicator.information_source: IndicatorNode["InformationSource"] = str(indicator.information_source)
    if indicator.likely_impact: IndicatorNode["LikelyImpact"] = str(indicator.likely_impact)
    if indicator.negate: IndicatorNode["IndicatorNegate"] = indicator.negate
    if indicator.producer: IndicatorNode["Producer"] = str(indicator.producer)
    if indicator.short_description: IndicatorNode["ShortDescription"] = str(indicator.short_descriptions)
    if indicator.suggested_coas: IndicatorNode["SuggestedCOA"] = str(indicator.suggested_coas)
    if indicator.timestamp: IndicatorNode["Timestamp"] = str(indicator.timestamp)
    if indicator.title: IndicatorNode["Title"] = indicator.title
    if indicator.version: IndicatorNode["Version"] = indicator.version
    if indicator.observable_composition_operator:
        IndicatorNode["CompositeIndicatorOperator"] = indicator.observable_composition_operator

    if indicator.description:
        if indicator.description.value: IndicatorNode["IndicatorDescription"] = indicator.description.value
    if indicator.sightings:
        IndicatorNode["SightingsCount"] = indicator.sightings.sightings_count
        for s in indicator.sightings:
            if s.timestamp and s.timestamp_precision:
                IndicatorNode["SightingsTimestamp"] = str(s.timestamp)
                IndicatorNode["SightingsTimestampPrecision"] = str(s.timestamp_precision)
                #print "Timestamp " + str(s.timestamp) + " with precision upto " + s.timestamp_precision
            if s.confidence: IndicatorNode["SightingsConfidence"] = s.confidence
            if s.description: IndicatorNode["SightingsDescription"] = s.description
            if s.reference: IndicatorNode["SightingsReference"] = s.reference
            if s.related_observables: IndicatorNode["SightingsRelatedObservables"] = pprint(s.related_observables)
            if s.source: IndicatorNode["SightingsSource"] = pprint(s.source)

    if indicator.indicator_types:
        stixGraph.run("CREATE CONSTRAINT ON (n:AllowedIndicatorTypesNode) ASSERT n.Description is UNIQUE")
        AllowedIndicatorTypesNode = Node("AllowedIndicatorTypesNode", Description="All allowed Indicator Types")

        stixGraph.run("CREATE CONSTRAINT ON (n:IndicatorTypeNode) ASSERT n.IndicatorType is UNIQUE")

        for keyInd in indicator.indicator_types:
            if keyInd.value: IndicatorNode["IndicatorTypeValue"] = keyInd.value
            keyIndValueList.append(keyInd.value)
            if keyInd.xsi_type: IndicatorNode["xsiType"] = keyInd.xsi_type
            AllowedIndicatorTypesNode[keyInd.TERM_ANONYMIZATION] = "TERM_ANONYMIZATION"
            AllowedIndicatorTypesNode[keyInd.TERM_C2] =  "TERM_C2"
            AllowedIndicatorTypesNode[keyInd.TERM_COMPROMISED_PKI_CERTIFICATE] = "TERM_COMPROMISED_PKI_CERTIFICATE"
            AllowedIndicatorTypesNode[keyInd.TERM_DOMAIN_WATCHLIST] = "TERM_DOMAIN_WATCHLIST"
            AllowedIndicatorTypesNode[keyInd.TERM_EXFILTRATION] =  "TERM_EXFILTRATION"
            AllowedIndicatorTypesNode[keyInd.TERM_FILE_HASH_WATCHLIST] =  "TERM_FILE_HASH_WATCHLIST"
            AllowedIndicatorTypesNode[keyInd.TERM_HOST_CHARACTERISTICS] =  "TERM_HOST_CHARACTERISTICS"
            AllowedIndicatorTypesNode[keyInd.TERM_IMSI_WATCHLIST] =  "TERM_IMSI_WATCHLIST"
            AllowedIndicatorTypesNode[keyInd.TERM_MALWARE_ARTIFACTS] = "TERM_MALWARE_ARTIFACTS"
            AllowedIndicatorTypesNode[keyInd.TERM_LOGIN_NAME] =  "TERM_LOGIN_NAME"
            AllowedIndicatorTypesNode[keyInd.TERM_IMEI_WATCHLIST] =  "TERM_IMEI_WATCHLIST"
            AllowedIndicatorTypesNode[keyInd.TERM_IP_WATCHLIST] =  "TERM_IP_WATCHLIST"
            AllowedIndicatorTypesNode[keyInd.TERM_URL_WATCHLIST] = "TERM_URL_WATCHLIST"
            AllowedIndicatorTypesNode[keyInd.TERM_MALICIOUS_EMAIL] = "TERM_MALICIOUS_EMAIL"

            if keyInd.TERM_ANONYMIZATION != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                                IndicatorTypeValue = keyInd.TERM_ANONYMIZATION)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_ANONYMIZATION")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_C2 != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                                IndicatorTypeValue = keyInd.TERM_C2)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_C2")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_COMPROMISED_PKI_CERTIFICATE:
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                                IndicatorTypeValue = keyInd.TERM_COMPROMISED_PKI_CERTIFICATE)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_COMPROMISED_PKI_CERTIFICATE")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_DOMAIN_WATCHLIST != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                                IndicatorTypeValue = keyInd.TERM_DOMAIN_WATCHLIST)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_DOMAIN_WATCHLIST")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass


            if keyInd.TERM_EXFILTRATION != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                                IndicatorTypeValue = keyInd.TERM_EXFILTRATION)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_EXFILTRATION")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_FILE_HASH_WATCHLIST != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                                IndicatorTypeValue = keyInd.TERM_FILE_HASH_WATCHLIST)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_FILE_HASH_WATCHLIST")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_HOST_CHARACTERISTICS != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                                IndicatorTypeValue = keyInd.TERM_HOST_CHARACTERISTICS)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_HOST_CHARACTERISTICS")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_IMEI_WATCHLIST != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                        IndicatorTypeValue = keyInd.TERM_IMEI_WATCHLIST)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_IMEI_WATCHLIST")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_IMSI_WATCHLIST != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                        IndicatorTypeValue = keyInd.TERM_IMSI_WATCHLIST)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_IMSI_WATCHLIST")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_IP_WATCHLIST != None :
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                        IndicatorTypeValue = keyInd.TERM_IP_WATCHLIST)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_IP_WATCHLIST")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_LOGIN_NAME:
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                        IndicatorTypeValue = keyInd.TERM_LOGIN_NAME)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_LOGIN_NAME")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_MALICIOUS_EMAIL:
                nodeType = Node("IndicatorTypeNode", Description="To Group Indicators based on their Type",
                                IndicatorTypeValue= keyInd.TERM_MALICIOUS_EMAIL)

                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_MALICIOUS_EMAIL")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_MALWARE_ARTIFACTS != None:
                nodeType = Node("IndicatorTypeNode", Description="To Group Indicators based on their Type",
                                IndicatorTypeValue=keyInd.TERM_MALWARE_ARTIFACTS)
                try:
                    relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                                IndicatorType = "TERM_MALWARE_ARTIFACTS")
                    stixGraph.merge(relIndType)
                except ConstraintError:
                    pass

            if keyInd.TERM_URL_WATCHLIST != None:
                nodeType = Node("IndicatorTypeNode",Description="To Group Indicators based on their Type",
                        IndicatorTypeValue = keyInd.TERM_URL_WATCHLIST)
            try:
                relIndType= Relationship(nodeType, "IndicatorTypesLink", AllowedIndicatorTypesNode,
                                         IndicatorType = "TERM_URL_WATCHLIST")
                stixGraph.merge(relIndType)
            except ConstraintError:
                pass

        try:
            relAllowInit = Relationship(init_node, "AllowedIndicatorTypesGraphLink", AllowedIndicatorTypesNode,
                                connect="Easy to find indicators of a particular type")
            stixGraph.merge(relAllowInit)
        except ConstraintError:
            pass

    if indicator.kill_chain_phases:
        for phase in indicator.kill_chain_phases:
            '''
            if phase.kill_chain_id:
                print "Kill Chain ID- " + str(phase.kill_chain_id)
                print "Kill Chain Name: " + str(kill_chains[phase.kill_chain_id])
            if phase.kill_chain_name: print "\tKill Chain Name- " + str(phase.kill_chain_name)
            if phase.phase_id: print "Phase ID- " + str(phase.phase_id)
            if phase.name: print "\tPhase Name- " + str(phase.name)
            if phase.ordinality: print "\tOrdinality- " + str(phase.ordinality)
            '''
            ######################CONNECT kill chain phase TO TTPKillChainNode's kill chain phase ?

        phaseNode = stixGraph.find_one("KillChainPhaseNode", property_key="PhaseName", property_value=phase.name)
        #stixGraph.run("CREATE CONSTRAINT ON (n:IndicatorNode) ASSERT n.ID IS UNIQUE")
        if phaseNode and IndicatorNode:
            relPhase = Relationship(phaseNode, "IndicatorKillChainPhaseLink", IndicatorNode, ID=indicator.id_, KillChainID=phase.kill_chain_id,
                                       PhaseID = phase.phase_id)
            try:
                stixGraph.merge(relPhase)
            except AttributeError:
                pass

    if indicator.composite_indicator_expression:
        headNode = stixGraph.find_one("HeaderNode", property_key="STIXFileID", property_value=StixFileID)
        stixGraph.run("CREATE CONSTRAINT ON (n:IndicatorNode) ASSERT n.ID IS UNIQUE")
        if headNode and IndicatorNode:
            relHead = Relationship(headNode, "HeaderIndicatorLink", IndicatorNode, ID=indicator.id_, STIXFileID=StixFileID,
                                       CompositeIndicatorOperator=indicator.observable_composition_operator)
            try:
                stixGraph.merge(relHead)
            except ConstraintError:
                pass
            except AttributeError:
                pass

    #stixGraph.merge(rel)
    if indicator.observables:
        for obs in indicator.observables:
            #obs, StixFileID, objRelated, indicatorID, incidentID
            parse_observable(obs, StixFileID, indicator.id_, None)
            obsNode = stixGraph.find_one("ObservableNode", property_key="ObservableID", property_value= obs.id_)
            if obsNode:
                relInd = Relationship(IndicatorNode,"IndicatorObservableLink",
                                      obsNode,  STIXFileID= StixFileID,
                                      IndicatorID = indicator.id_,
                                      ObservableID = obs.id_ ,
                                      connect="Indicator-Observable Link, if it exists. \
                                              http://stixproject.github.io/data-model/1.2/cybox/ObservableType/")
                stixGraph.merge(relInd)


    for indValKey in keyIndValueList:
        indTypeNode = stixGraph.find_one("IndicatorTypeNode", property_key="IndicatorTypeValue", property_value=indValKey)
        try:
            relIndType = Relationship(indTypeNode, "IndicatorTypeLink",IndicatorNode,IndicatorTypeValue = indValKey)
            stixGraph.merge(relIndType)
        except ConstraintError:
            pass
        except AttributeError:
            pass

    '''
    # FUTURE WORK TO MAKE IT STIX COMPLIANT
    if indicator.indicated_ttps:
        parse_indicated_ttps(indicator.indicated_ttps)
    if indicator.related_campaigns:
        parse_indicator_related_campaigns(indicator.related_campaigns)
    if indicator.related_indicators:
        parse_indicator_related_indicators(indicator.related_indicators)
    if indicator.related_packages:
        parse_indicator_related_packages(indicator.related_packages)
    if indicator.short_descriptions:
        parse_indicator_short_descriptions(indicator.short_descriptions)
    '''

def parse_indicators(indicators, kill_chains, kill_chain_phases, StixFileID):
    print "*****************************Indicators*******************************************************"
    compInd = None
    indList = []
    for indicator in indicators:
        if (indicator.composite_indicator_expression):
            compInd = indicator.id_
        else:
            indList.append(indicator.id_)

    for indicator in indicators:
        parse_indicator(indicator, indicator.id_, kill_chains, kill_chain_phases, StixFileID)

    for ind in indList:
        if compInd:
            compIndNode = stixGraph.find_one("IndicatorNode", property_key="ID", property_value=compInd)
            indNode = stixGraph.find_one("IndicatorNode", property_key="ID", property_value= ind)
            if compIndNode and indNode:
                relInd = Relationship(compIndNode, "CompositionIndicatorLink", indNode,
                                      CompositionOperator=indicator.observable_composition_operator)
                try:
                    stixGraph.merge(relInd)
                except ConstraintError:
                    pass


def parse_ttps(ttp, kill_chains, kill_chain_phases, StixFileID):
    print "***********************************************TTPS*********************************************"
    for tactic in ttp:
        #print("TTPID: "+ tactic.id_)
        stixGraph.run("CREATE CONSTRAINT ON (n:TTPKillChainNode) ASSERT n.Name IS UNIQUE")
        desc= " Tactics, Techniques, and Procedures (TTP) contains leverage that help salve a threat." \
              "It contains information about vulnerabilities, misconfigurations, weaknesses likely to be targeted and " \
              "actions taken in the past to overcome them."
        TTPNode = Node("TTPNode", TTPDesc = desc, TTPID = tactic.id_ , Timestamp = str() )

        if tactic.title: TTPNode["TTPTitle"]= tactic.title
        if tactic.behavior:
            if tactic.behavior.attack_patterns:
                for i,behave in enumerate(tactic.behavior.attack_patterns):
                    TTPNode["TTP_CAPEC_ID"+str(i)]= str(behave.capec_id)
                    TTPNode["TTPAttackPatternDescription"+str(i)]= str(behave.description)
            if tactic.behavior.exploits:
                for i, exp in enumerate(tactic.behavior.exploits):
                    if exp.id_ : TTPNode["TTPExploitsID"]= str(exp.id_)
                    if exp.description: TTPNode["TTPExploitsDescription"+str(i)]= str(exp.description)
                    if exp.title: TTPNode["TTPExploitsTitle"+str(i)]= str(exp.title)
            if tactic.behavior.malware_instances:
                for i,sample in enumerate(tactic.behavior.malware_instances):
                    TTPNode["TTPMalwareSample"+str(i)]= str(sample.names[0])
                    TTPNode["TTPMalwareType"+str(i)]= str(sample.types[0])
                    TTPNode["TTPMalwareID"+str(i)]= sample.id_
        #intended_effects, kill_chain_phases, related_packages, related_ttps, victim_targeting
        stixGraph.merge(TTPNode)
    for chain in ttp.kill_chains:
        kill_chains[chain.id_] = chain.name

        desc = "Contains kill chains that can be adopted when we encounter a threat.Connected to initNode"
        stixGraph.run("CREATE CONSTRAINT ON (n:TTPKillChainNode) ASSERT n.Name IS UNIQUE")
        TTPKillChainNode = Node("TTPKillChainNode", Description=desc, Name=chain.name, Definer=chain.definer, Reference=chain.reference,
                       NoOfPhases=chain.number_of_phases, ID=chain.id_, STIXFileID=StixFileID)

        rel = Relationship(init_node, "TTPGraphLink", TTPKillChainNode, connect="To make sure graph isn't disconnected")
        try:
            stixGraph.merge(rel)
        except ConstraintError:
            pass
        for phase in chain.kill_chain_phases:
            kill_chain_phases[phase.phase_id] = str(phase.name)
            #print "Phases: [" + str(phase.phase_id) + "][" + str(phase.ordinality) + "] = " + str(phase.name)

            desc = "Each Kill Chain is defined in terms of phases in which we caught a particular threat."
            stixGraph.run("CREATE CONSTRAINT ON (n:KillChainPhaseNode) ASSERT n.PhaseName IS UNIQUE")
            KillChainPhaseNode = Node("KillChainPhaseNode", Description=desc, Ordinality=phase.ordinality,
                                      PhaseName=phase.name, ID=phase.phase_id, Chain_ID=chain.id_,
                                      STIXFileID=StixFileID)
            reln = Relationship(TTPKillChainNode, "TTPKillChainPhaseLink", KillChainPhaseNode, connect="Phases Of KillChain")

            try:
                stixGraph.merge(reln)
            except ConstraintError:
                pass


def parse_reports(reports):
    print "*****************************Reports*******************************************************"
    for report in reports:
        ReportNode = Node("ReportNode", ReportID = report.id_ )


        if report.timestamp: ReportNode["Timestamp"] = str(report.timestamp)
        if report.observables: ReportNode["ReportObservables"]= str(report.observables)

        if report.header:
            ReportNode["ReportTitle"]= str(report.header.title)
            ReportNode["ReportDesc"]= str(report.header.description)
            ReportNode["ReportSource"]= str(report.header.information_source.time.produced_time.value)
            ReportNode["ReportIntent"]= str(report.header.intents[0].value)

            if report.campaigns:
                for i,camp in enumerate(report.campaigns):
                    ReportNode["ReportCampaignID"+str(i)]= camp.idref
                    campNode = stixGraph.find_one("CampaignNode",property_key="CampaignID", property_value=camp.idref )
                    if campNode:
                        relCampaignReport= Relationship(campNode, "CampaignReportLink", ReportNode,
                            Description="Campaigns in a Report", CampaignID = camp.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relCampaignReport)
                        except:
                            pass

            if report.courses_of_action:
                for i,coa in enumerate(report.courses_of_action):
                    ReportNode["ReportCOAID"+str(i)]= coa.idref
                    coaNode = stixGraph.find_one("COANode",property_key="COAID", property_value=coa.idref )
                    if coaNode:
                        relCOAReport= Relationship(coaNode, "COAReportLink", ReportNode,
                            Description="COA in a Report", COAID = coa.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relCOAReport)
                        except:
                            pass

            if report.exploit_targets:
                for i,targ in enumerate(report.exploit_targets):
                    ReportNode["ReportExploitTargetID"+str(i)]= targ.idref
                    targNode = stixGraph.find_one("ExploitTargetNode",property_key="ExploitTargetID", property_value=targ.idref)
                    if targNode:
                        relTargetReport= Relationship(targNode, "ExploitargetReportLink", ReportNode,
                            Description="Exploit Targets in a Report", ExploitTargetID = targ.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relTargetReport)
                        except:
                            pass

            if report.incidents:
                for i,inc in enumerate(report.incidents):
                    ReportNode["ReportIncident"+str(i)]= inc.idref
                    incNode = stixGraph.find_one("IncidentNode",property_key="IncidentID", property_value=inc.idref )
                    if incNode:
                        relIncidentReport= Relationship(incNode, "IncidentReportLink", ReportNode,
                            Description="Incidents in a Report", IncidentID = inc.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relIncidentReport)
                        except:
                            pass

            if report.indicators:
                for i,indi in enumerate(report.indicators):
                    ReportNode["ReportIndicator"+str(i)]= indi.idref
                    indiNode = stixGraph.find_one("IndicatorNode",property_key="ID", property_value=indi.idref )
                    if indiNode:
                        relIndicatorReport= Relationship(indiNode, "IndicatorReportLink", ReportNode,
                            Description="Indicators in a Report", IncidentID = indi.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relIndicatorReport)
                        except:
                            pass

            if report.related_reports:
                for i,rep in enumerate(report.related_reports):
                    ReportNode["ReportRelatedReports"+str(i)]= rep.idref
                    repNode = stixGraph.find_one("ReportNode",property_key="ReportID", property_value=rep.idref )
                    if repNode:
                        relReports= Relationship(repNode, "RelatedReportLink", ReportNode,
                            Description="Related Reports", RelatedReportID = rep.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relReports)
                        except:
                            pass

            if report.threat_actors:
                for i,actor in enumerate(report.threat_actors):
                    ReportNode["ReportActor"+str(i)]= actor.idref
                    actorNode = stixGraph.find_one("ThreatActorNode",property_key="ThreatActorID", property_value=actor.idref)
                    if actorNode:
                        relActorReport= Relationship(actorNode, "ThreatActorReportLink", ReportNode,
                            Description="Threat Actors in a Report", ThreatActorID = actor.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relActorReport)
                        except:
                            pass

            if report.ttps:
                for i,ttp in enumerate(report.ttps):
                    ReportNode["ReportTTP"+str(i)]= ttp.idref
                    indiNode = stixGraph.find_one("TTPNode",property_key="TTPID", property_value=ttp.idref )
                    if indiNode:
                        relIndicatorReport= Relationship(indiNode, "TTPReportLink", ReportNode,
                            Description="Indicators in a Report", TTPID = ttp.idref,
                             ReportID = report.id_)
                        try:
                            stixGraph.merge(relIndicatorReport)
                        except:
                            pass


def parse_COA(course_of_action):
    print "*****************************COA*******************************************************"
    for coa in course_of_action:
        COANode = Node("COANode", Desc= "CoursesOfAction", COAID=coa.id_)
        COANode["COACost"]= str(coa.cost.value)
        COANode["COAEfficacy"]= str(coa.efficacy.value)
        COANode["COAImpact"]= str(coa.impact.value)
        COANode["COAImpactDescription"]= str(coa.impact.description)
        COANode["COAObjectiveDescription"]= str(coa.objective.description)
        COANode["COAObjectiveApplicabilityConfidence"]= str(coa.objective.applicability_confidence.value)
        for obs in coa.parameter_observables.observables:
            COANode["COAObservableProperty"]= str(obs.object_.properties.address_value)
        COANode["COAStage"]= str(coa.stage)
        COANode["COAType"]= str(coa.type_)
        COANode["COATitle"]= coa.title
        stixGraph.merge(COANode)

def parse_exploit_target(exploit_targets):
    print "*****************************Exploit Target*******************************************************"
    for target in exploit_targets:
        ExploitTargetNode = Node("ExploitTargetNode", Title="Exploit Targets", ExploitTargetID=target.id_)
        if target.description: ExploitTargetNode["ExploitTargetDescription"]= str(target.description)
        if target.handling: ExploitTargetNode["ExploitTargetHandling"]= str(target.handling)
        if target.information_source: ExploitTargetNode["ExploitTargetSource"]= str(target.information_source)
        if target.potential_coas: ExploitTargetNode["ExploitTargetPotentialCOA"]= str(target.potential_coas)
        if target.related_exploit_targets: ExploitTargetNode["RelatedExploitTargets"]= str(target.related_exploit_targets)
        if target.related_packages: ExploitTargetNode["ExploitTargetRelatedPackages"]= str(target.related_packages)
        if target.timestamp: ExploitTargetNode["ExploitTargetTimestamp"]= str(target.timestamp)
        if target.title: ExploitTargetNode["ExploitTargetTitle"]= target.title
        if target.vulnerabilities:
            for i, vulnerable in enumerate(target.vulnerabilities):
                ExploitTargetNode["ExploitTargetVulnerabilityCVE"+str(i)]= vulnerable.cve_id
        if target.weaknesses:
            for i,weak in enumerate(target.weaknesses):
                ExploitTargetNode["ExploitTargetWeaknesses"+str(i)]= str(target.weaknesses)
        stixGraph.merge(ExploitTargetNode)

def parse_campaigns(pkg):
    print "*****************************Campaigns*******************************************************"
    for camp in pkg.campaigns:
        '''
        print("-------------------------------\n")
        print"CampaignTitle" + str(camp.title)
        print "CampaignID" +str(camp.id_)
        print "Timestamp"+ str(camp.timestamp)

        #Indicator to campaign relationship is broken currently: Available in versions before 1.1 (idref is support issue? )
        for indicator in campaign.related_indicators:
            print("  - Related To: " + indicators[indicator.item.idref].title)
        '''
        CampaignNode = Node("CampaignNode",CampaignTitle = camp.title ,CampaignID=camp.id_, Timestamp = str(camp.timestamp))
        relatedTTP = []
        relatedActors=[]
        relatedIncidents =[]
        if camp.attribution:
            print "---"
            for i,attrib in enumerate(camp.attribution):
                if attrib[0].item.title: CampaignNode["AttributedActor"+str(i)] = attrib[0].item.title
                if attrib[0].item.description: CampaignNode["AttributedActorDesc"+str(i)] = attrib[0].item.description
                if attrib[0].item.id_:
                    CampaignNode["AttributedActorID"+str(i)]= attrib[0].item.id_
                    relatedActors.append(attrib[0].item.id_)
                if attrib[0].item.timestamp: CampaignNode["AttributedActorTimestamp"+ str(i)]= str(attrib[0].item.timestamp)
                if attrib[0].item.confidence:
                    CampaignNode["AttributedActorConfidence"+str(i)] = str(attrib[0].item.confidence.value.value)

                '''
                actorNode = stixGraph.find_one("ThreatActorNode", property_key="ThreatActorID", property_value=attrib[0].item.id_)
                try:
                    relActorCampaign= Relationship(campNode, "ThreatActorCampaignLink", actorNode,
                                            Description="Campaign Actor Attribution", ActorID = attrib[0].item.id_,
                                            ActorTitle = attrib[0].item.title , Timestamp= str(attrib[0].item.timestamp))
                    stixGraph.merge(relActorCampaign)
                except ConstraintError:
                    pass
                '''
        if camp.related_incidents:
            for i,rel in enumerate(camp.related_incidents):
                CampaignNode["RelatedIncidentID"+str(i)] = str(rel.item.idref)
                relatedIncidents.append(rel.item.idref)
                if rel.item.description: CampaignNode["RelatedTTPDesc"+str(i)] = rel.item.description
                if rel.relationship: CampaignNode["RelatedIncidentRelationship"+str(i)] = rel.relationship
                if rel.information_source: CampaignNode["RelatedIncidentSource"+str(i)] = rel.information_source
                if rel.confidence: CampaignNode["RelatedIncidentConfidence"+str(i)] = rel.confidence
                #affected_assets, attributed_threat_actors, categories, coa_requested ,coa_taken,
                # coordinators, discovery_methods,history,reporter, security_compromise
                #intended_effects, leveraged_ttps, related_incodents, related_indicators,
                # relatedobservables, related_packages, responders, victims

        if camp.related_ttps:
            for i,tactic in enumerate(camp.related_ttps):
                if tactic.relationship:
                    CampaignNode["CampaignTTPRelationship"+str(i)] = str(tactic.relationship)
                    #print "CampaignTTPRelationship : "+ str(tactic.relationship)
                if tactic.item:
                    if tactic.item.idref: CampaignNode["RelatedTTPsID_"+str(i)] = str(tactic.item.idref)
                    relatedTTP.append(tactic.item.idref)

                #find TTPNode with idref = tactic.item.idref
                # = stixGraph.find_one("TTPNode",property_key="TTPID", property_value=tactic.item.idref)
                ttp = pkg.find(tactic.item.idref)
                if ttp:
                    CampaignNode["RelatedTTPTitle_"+str(i)] = str(ttp.title)
                    #print("RelatedTTP: " + str(ttp.title))
                    if ttp.victim_targeting.targeted_information:
                        for j,target in enumerate(ttp.victim_targeting.targeted_information):
                            #print("\tTarget: " + str(target))
                            CampaignNode["RelatedTTPVictim_"+str(i)+"_"+str(j)] = str(target)

def parse_incidents(incidents, STIXFileID):
    print "*****************************Incidents*******************************************************"

    for inc in incidents:
        leveragedTTPs=[]
        relatedObs=[]
        # attributed_threat_actors, handling, history, impact_assessment, reporter, security_compromise, status, version,
        # categories, coa_requested, coa_taken,coordinators, discovery_methods, external_ids, intended_effects, leveraged_ttps ,
        # related_incidents, related_indicators, related_observables, related_packages, responders, victims
        IncidentNode = Node("IncidentNode",IncidentID=inc.id_, Timestamp = str(inc.timestamp))
        stixGraph.run("CREATE CONSTRAINT ON (n:IncidentNode) ASSERT n.IncidentID IS UNIQUE")

        if inc.title: IncidentNode["IncidentTitle"] = inc.title
        if inc.reporter: IncidentNode["IncidentReporter" ]= inc.reporter.identity.name
        if inc.description: IncidentNode["IncidentDesc"]= str(inc.description)
        if inc.confidence: IncidentNode["IncidentConfidence"]= str(inc.confidence.value)
        if inc.time:
            IncidentNode["IncidentInitialCompromise"]= str(inc.time.initial_compromise.value)
            IncidentNode["IncidentDiscovery"]=str(inc.time.incident_discovery.value)
            IncidentNode["IncidentRestoration"]= str(inc.time.restoration_achieved.value)
            IncidentNode["IncidentReported"] = str(inc.time.incident_reported.value)

        if inc.impact_assessment:
            for i, impact in enumerate(inc.impact_assessment.effects):
                IncidentNode["IncidentImpact"+ str(i)] = str(impact)

        if inc.victims:
            for i,victim in enumerate(inc.victims):
                IncidentNode["IncidentVictim"+str(i)]= str(victim.name)

        if inc.leveraged_ttps:
            for i,relation in enumerate(inc.leveraged_ttps):
                IncidentNode["IncidentRelatedTTP"+str(i)]= str(relation.relationship)
                IncidentNode["IncidentRelatedTTPID"+str(i)]= str(relation.item.idref)
                leveragedTTPs.append(relation.item.idref)
        #Similar code for related_packages, related_indicators, related_incidents
        if inc.related_observables:
            for i,obs in enumerate(inc.related_observables):
                IncidentNode["IncidentObservableID"+str(i)]=obs.item.id_
                IncidentNode["IncidentObservableRelation"+str(i)]= str(obs.relationship)
                IncidentNode["IncidentObservableFileName"+str(i)]= str(obs.item.object_.properties.file_name)
                IncidentNode["IncidentObservableFilesize"+str(i)]= str(obs.item.object_.properties.size_in_bytes)
                IncidentNode["IncidentObservableSHA256Digest"+str(i)]= str(obs.item.object_.properties.hashes[0].simple_hash_value)
        if inc.affected_assets:
            for i,asset in enumerate(inc.affected_assets):
                if asset.description: IncidentNode["IncidentAffectedAssetsDesc"+str(i)]=  str(asset.description)
                if asset.type_: IncidentNode["IncidentAffectedAssetsType"+str(i)]= str(asset.type_)
                if asset.type_.count_affected: IncidentNode["IncidentAffectedAssetsCount"+str(i)]= str(asset.type_.count_affected)
                if asset.business_function_or_role: IncidentNode["IncidentAffectedAssetsRole"+str(i)]= str(asset.business_function_or_role)
                if asset.ownership_class: IncidentNode["IncidentAffectedAssetsOwner"+str(i)]= str(asset.ownership_class)
                if asset.management_class:IncidentNode["IncidentAffectedAssetsManager"+str(i)]= str(asset.management_class)
                if asset.location_class: IncidentNode["IncidentAffectedAssetsLocation"+str(i)]=  str(asset.location_class)

            if asset.nature_of_security_effect:
                for i,effect in enumerate(asset.nature_of_security_effect):
                    if effect.property_: IncidentNode["IncidentSecurityEffectProperty"+str(i)]= str(effect.property_)
                    if effect.description_of_effect: IncidentNode["IncidentSecurityEffectDesc"+str(i)]= str(effect.description_of_effect)
                    if effect.non_public_data_compromised:
                        IncidentNode["IncidentSecurityEffectCompromised"+str(i)]= str(effect.non_public_data_compromised)
                    if effect.non_public_data_compromised.data_encrypted:
                        IncidentNode["IncidentSecurityEffectCompromisedEncrypted"+str(i)]= str(effect.non_public_data_compromised.data_encrypted)
        stixGraph.merge(IncidentNode)

        for lev in leveragedTTPs:
            ttpNode = stixGraph.find_one("TTPNode", property_key="TTPID", property_value=lev)
            if ttpNode:
                relTTPInc = Relationship(ttpNode, "TTPIncidentLink", IncidentNode,
                                           IncidentID = inc.id_, TTPID = lev)
                stixGraph.merge(relTTPInc)



def parse_threat_actors(pkg):
    print "*****************************Threat Actors*******************************************************"
    for actor in pkg.threat_actors:
        observedTTPs=[]
        ThreatActorNode = Node("ThreatActorNode",Title = "Contains Threat Actors related to TTP", ThreatActorID=actor.id_, Timestamp = str(actor.timestamp))
        stixGraph.run("CREATE CONSTRAINT ON (n:ThreatActorNode) ASSERT n.ThreatActorID IS UNIQUE")

        if actor.title: ThreatActorNode["ActorTitle"] = actor.title
        if actor.description: ThreatActorNode["ActorDescription"]= str(actor.description)
        if actor.confidence: ThreatActorNode["ActorConfidence"]= str(actor.confidence.value.value)
        if actor.identity: ThreatActorNode["ThreatActorName"]= str(actor.identity.name)

        # associate_campaigns, associated_actors, planning_and_operational_supports, types...
        if actor.motivations:
            for i,motivate in enumerate(actor.motivations):
                if motivate.value: ThreatActorNode["Motivation"+ str(i)]= motivate.value.value
                if motivate.confidence: ThreatActorNode["MotivationConfidence"+str(i)]= motivate.confidence
                if motivate.description: ThreatActorNode["MotivationDescription"+str(i)]= motivate.description
                if motivate.source: ThreatActorNode["MotivationSource"+str(i)] = motivate.source
                if motivate.timestamp: ThreatActorNode["MotivationTimestamp"+str(i)] =  str(motivate.timestamp)

        if actor.intended_effects:
            for i,intend in enumerate(actor.intended_effects):
                if intend.value: ThreatActorNode["IntendedEffect"+str(i)]= intend.value.value
                if intend.confidence: ThreatActorNode["IntendedEffectConfidence"+str(i)]= intend.confidence
                if intend.description: ThreatActorNode["IntendedEffectDescription"+str(i)]= intend.description
                if intend.source: ThreatActorNode["IntendedEffectSource"+str(i)]= intend.source
                if intend.timestamp: ThreatActorNode["IntendedEffectTimestamp"+str(i)]= str(intend.timestamp)

        if actor.sophistications:
            for i,sophisticate in enumerate(actor.sophistications):
                if sophisticate.value: ThreatActorNode["Sophistication"+str(i)]= sophisticate.value.value
                if sophisticate.confidence: ThreatActorNode["SophisticationConfidence"+str(i)]= sophisticate.confidence
                if sophisticate.description: ThreatActorNode["SophisticationDescription"+str(i)]= sophisticate.description
                if sophisticate.source: ThreatActorNode["SophisticationSource"+str(i)]= sophisticate.source
                if sophisticate.timestamp: ThreatActorNode["SophisticationTimestamp"+str(i)]= str(sophisticate.timestamp)

        if actor.observed_ttps:
            for i,ttp in enumerate(actor.observed_ttps):
                observedTTPs.append(ttp.item.idref)
                ThreatActorNode["ObservedTTP_ID"+str(i)]= ttp.item.idref
                if ttp.relationship: ThreatActorNode["ObservedTTPRelationship"+str(i)]=  str(ttp.relationship)
                if ttp.information_source: ThreatActorNode["ObservedTTPSource"+str(i)]=  ttp.information_source
                if ttp.confidence: ThreatActorNode["ObservedTTPConfidence"+str(i)]= ttp.confidence
                #Link Observable TTP
                #print "RelatedTTP: " + str(pkg.find(ttp.item.idref).title)

        stixGraph.merge(ThreatActorNode)

        for ob in observedTTPs:
            ttpNode = stixGraph.find_one("TTPNode", property_key="TTPID", property_value=ob)
            if ttpNode:
                relTTPActor = Relationship(ttpNode, "TTPActorLink", ThreatActorNode,
                                           ThreatActorID = actor.id_, TTPID = ttp.item.idref)
                stixGraph.merge(relTTPActor)

def print_parsed_data(pkg):
    kill_chains = {}
    kill_chain_phases = {}

    if pkg.stix_header:
        parse_header(pkg.stix_header, pkg._id)

    if pkg.exploit_targets:
        parse_exploit_target(pkg.exploit_targets)
    if pkg.related_packages:
        logging.info('Related Packages to be handled separately..')

    if pkg.observables:
        parse_observables(pkg.observables.observables, pkg._id, None, None)

    if pkg.indicators:
        parse_indicators(pkg.indicators, kill_chains, kill_chain_phases, pkg._id)

    if pkg.incidents:
        parse_incidents(pkg.incidents, pkg._id)

    if pkg.courses_of_action:
        parse_COA(pkg.courses_of_action)

    if pkg.ttps:
        parse_ttps(pkg.ttps, kill_chains, kill_chain_phases, pkg._id)

    if pkg.threat_actors:
        parse_threat_actors(pkg)

    if pkg.campaigns:
        parse_campaigns(pkg)

    if pkg.reports:
        parse_reports(pkg.reports)

def parse_file(myfile):
    f = open(myfile)
    #parse the input file
    logging.info('Parsing input file '+str(f))
    '''
    stix_package = STIXPackage.from_xml(f)
    print_parsed_data(stix_package)

    '''
    try:
        stix_package = STIXPackage.from_xml(f)
    #graphMain(stix_package)
        print_parsed_data(stix_package)

    except ValueError:
        logging.info('Input file %s cannot be parsed', str(f))
        f.close()
        return

    #Close file
    f.close()

def test_file(myfile):
    logging.info('Opening test file to parse')
    parse_file(myfile)


def main():
    test_file('../TEST/Tryout.xml')
    #test_file('../TEST/11.xml')
    #test_files()
    #test_GreenIOC()

if __name__ == '__main__':
    main()

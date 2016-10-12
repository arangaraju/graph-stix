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
#stixGraph.run("DROP CONSTRAINT ON (t:TTPNode)ASSERT t.ID IS UNIQUE")

#stixGraph.run("MATCH (n) DETACH DELETE n")
#Init Node
desc = "This Node will connect to LM Kill Chain, all STIX Header,Observable nodes to make sure the graph is not disconnected"
NodeID = "InitNode"
stixGraph.run("CREATE CONSTRAINT ON (n:InitNode) ASSERT n.ID IS UNIQUE")
init_node = Node("StixGraph", Description=desc, ID=NodeID)
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


def parse_observables(observables, StixFileID):
    objRelated = {}
    for obs in observables:
        parse_observable(obs, StixFileID, objRelated)

    if objRelated:
        for key, val in objRelated:
            objNode = stixGraph.find_one("ObservableNode", property_key="ObjectID", property_value=key)
            relObjNode = stixGraph.find_one("ObservableNode", property_key="ObjectID", property_value= val)
            if relObjNode and ObservableNode:
                relPhase = Relationship(relObjNode, "RelatedObjectLink", ObservableNode,
                    ObjectID =key, RelatedObjectID = val)
                try:
                    stixGraph.merge(relPhase)
                except ConstraintError:
                    pass
                except AttributeError:
                    pass


def parse_observable(obs, StixFileID, objRelated):
    obj = obs.to_obj()
    if not obj or not hasattr(obj, "Object") or not hasattr(obj.Object, "Properties"): return
    prop = obj.Object.Properties

    ObservableNode = Node("ObservableNode", ObservableID=obs.id_, ObjectID=obj.Object.id,
                          xsiType=prop.xsi_type, STIXFileID=StixFileID)

    print "Observable: " + obs.id_  #Observable ID
    #obj = obs.get('object')
    print "Related Observable: " + obj.id
    #prop = obs.get('object').get('properties')

    print "XSI Type: " + prop.xsi_type

    if (type(prop) == FileObjectType):
        #prop.Accessed_Time
        #prop.Byte_Runs
        #prop.Compression_Comment
        #prop.Compression_Method
        #prop.Compression_Version
        #prop.Created_Time
        #prop.Custom_Properties
        #prop.Decryption_Key
        #prop.Device_Path
        #prop.Digital_Signatures
        #prop.Encryption_Algorithm
        #prop.Extracted_Features
        #prop.File_Attributes_List
        #prop.File_Extension
        #prop.File_Format
        #prop.File_Path
        #prop.Full_Path
        #prop.Hashes
        #prop.Magic_Number
        #prop.Modified_Time
        #prop.Packer_List
        #prop.Peak_Entropy
        #prop.Permissions
        #prop.Size_In_Bytes
        #prop.Sym_Links
        #prop.User_Owner
        #prop.is_masqueraded
        #prop.is_packed
        #prop.object_reference
        #prop.xsi_type

        #prop.File_Name.appears_random
        #prop.File_Name.apply_condition
        #prop.File_Name.bit_mask
        #prop.File_Name.condition
        #prop.File_Name.datatype
        #prop.File_Name.defanging_algorithm_ref
        #prop.File_Name.delimiter
        #prop.File_Name.extensiontype_
        #prop.File_Name.has_changed
        # prop.File_Name.id
        # prop.File_Name.idref
        # prop.File_Name.is_case_sensitive
        # prop.File_Name.is_defanged
        # prop.File_Name.is_defanged
        # prop.File_Name.is_obfuscated
        # prop.File_Name.obfuscation_algorithm_ref
        # prop.File_Name.observed_encoding
        # prop.File_Name.pattern_type
        # prop.File_Name.refanging_transform
        # prop.File_Name.refanging_transform_type
        # prop.File_Name.regex_syntax
        # prop.File_Name.trend
        # prop.File_Name.valueOf_

        try:
            print "Size(in Bytes) : " + str(prop.Size_In_Bytes.valueOf_)
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
                print "Hash(Type : Value) " + str(h) + ":" + str(hashVal)
                ht = "HashType" + str(i)
                hv = "HashValue" + str(i)
                ObservableNode[ht] = hash.Type.valueOf_
                ObservableNode[hv] = hashVal


    elif (type(prop) == AddressObjectType):
        print "-------------------------------------------------"
        #prop.Custom_Properties
        #prop.VLAN_Name
        #prop.VLAN_Num
        #prop.category
        #prop.is_destination
        #prop.is_source
        #prop.is_spoofed
        #prop.object_reference
        #prop.xsi_type

        #prop.Address_Value.appears_random
        #prop.Address_Value.apply_condition
        #prop.Address_Value.bit_mask
        #prop.Address_Value.condition
        #prop.Address_Value.datatype
        #prop.Address_Value.defanging_algorithm_ref
        #prop.Address_Value.delimiter
        #prop.Address_Value.extensiontype_
        #prop.Address_Value.has_changed
        # prop.Address_Value.id
        # prop.Address_Value.idref
        # prop.Address_Value.is_case_sensitive
        # prop.Address_Value.is_defanged
        # prop.Address_Value.is_defanged
        # prop.Address_Value.is_obfuscated
        # prop.Address_Value.obfuscation_algorithm_ref
        # prop.Address_Value.observed_encoding
        # prop.Address_Value.pattern_type
        # prop.Address_Value.refanging_transform
        # prop.Address_Value.refanging_transform_type
        # prop.Address_Value.regex_syntax
        # prop.Address_Value.trend
        # prop.Address_Value.valueOf_

        print "Address Value:\n\t(Apply Condition:Condition)-" + \
              prop.Address_Value.apply_condition + ":" + prop.Address_Value.condition
        print "\t(Category: Value) - " + prop.category + ":" + prop.Address_Value.valueOf_
        ObservableNode["Category"] = prop.category
        ObservableNode["AddressValue"] = prop.Address_Value.valueOf_
        ObservableNode["ApplyCondition"] = prop.Address_Value.apply_condition
        ObservableNode["Condition"] = prop.Address_Value.condition

    elif (type(prop) == URIObjectType):
        # prop.Custom_Properties
        # prop.object_reference
        # prop.type_
        # prop.xsi_type

        # prop.Value.appears_random
        # prop.Value.apply_condition
        # prop.Value.bit_mask
        # prop.Value.condition
        # prop.Value.datatype
        # prop.Value.defanging_algorithm_ref
        # prop.Value.delimiter
        # prop.Value.extensiontype_
        # prop.Value.has_changed
        # prop.Value.id
        # prop.Value.idref
        # prop.Value.is_case_sensitive
        # prop.Value.is_defanged
        # prop.Value.is_obfuscated
        # prop.Value.obfuscation_algorithm_ref
        # prop.Value.observed_encoding
        # prop.Value.pattern_type
        # prop.Value.refanging_transform
        # prop.Value.refanging_transform_type
        # prop.Value.regex_syntax
        # prop.Value.trend
        # prop.Value.valueOf_

        print "Type:" + prop.type_
        print "Apply_Condition:" + prop.Value.apply_condition
        print "condition:" + prop.Value.condition

        print "Value :" + prop.Value.valueOf_
        print "delimiter: " + prop.Value.delimiter

        ObservableNode["Type"] = prop.type_
        ObservableNode["ApplyCondition"] = prop.Value.apply_condition
        ObservableNode["Condition"] = prop.Value.condition
        ObservableNode["Delimiter"] = prop.Value.delimiter
        ObservableNode["Value"] = prop.Value.valueOf_


    elif type(prop) == EmailMessageObjectType:

        # prop.Custom_Properties
        # prop.Email_Server
        # prop.Links
        # prop..Raw_Body
        # prop.Raw_Header
        # prop.object_reference
        # prop.xsi_type

        # for file in prop.Attachments.File: #(LIST)
        # file.object_reference

        # prop.Header.BCC
        # prop.Header.Boundary
        # prop.Header.CC
        # prop.Header.Content_Type
        # prop.Header.Date
        # prop.Header.Errors_To
        # prop.Header.In_Reply_To
        # prop.Header.MIME_Version
        # prop.Header.Precedence
        # prop.Header.Received_Lines
        # prop.Header.Reply_To
        # prop.Header.To
        # prop.Header.User_Agent
        # prop.Header.X_Mailer
        # prop.Header.X_Originating_IP
        # prop.Header.X_Priority

        #prop.Header.From.Custom_Properties
        #prop.Header.From.VLAN_Name
        #prop.Header.From.VLAN_Num
        #prop.Header.From.category
        #prop.Header.From.is_destination
        #prop.Header.From.is_source
        #prop.Header.From.is_spoofed
        #prop.Header.From.object_reference
        #prop.Header.From.xsi_type

        #prop.Header.From.Address_Value.appears_random
        #prop.Header.From.Address_Value.apply_condition
        #prop.Header.From.Address_Value.bit_mask
        #prop.Header.From.Address_Value.condition
        #prop.Header.From.Address_Value.datatype
        #prop.Header.From.Address_Value.defanging_algorithm_ref
        #prop.Header.From.Address_Value.delimiter
        #prop.Header.From.Address_Value.extensiontype_
        #prop.Header.From.Address_Value.has_changed
        #prop.Header.From.Address_Value.id
        #prop.Header.From.Address_Value.idref
        #prop.Header.From.Address_Value.is_case_sensitive
        #prop.Header.From.Address_Value.is_defanged
        #prop.Header.From.Address_Value.is_defanged
        #prop.Header.From.Address_Value.is_obfuscated
        #prop.Header.From.Address_Value.obfuscation_algorithm_ref
        #prop.Header.From.Address_Value.observed_encoding
        #prop.Header.From.Address_Value.pattern_type
        #prop.Header.From.Address_Value.refanging_transform
        #prop.Header.From.Address_Value.refanging_transform_type
        #prop.Header.From.Address_Value.regex_syntax
        #prop.Header.From.Address_Value.trend
        #prop.Header.From.Address_Value.valueOf_


        # prop.Header.Message_ID.appears_random
        # prop.Header.Message_ID.apply_condition
        # prop.Header.Message_ID.bit_mask
        # prop.Header.Message_ID.condition
        # prop.Header.Message_ID.datatype
        # prop.Header.Message_ID.defanging_algorithm_ref
        # prop.Header.Message_ID.delimiter
        # prop.Header.Message_ID.extensiontype_
        # prop.Header.Message_ID.has_changed
        # prop.Header.Message_ID.id
        # prop.Header.Message_ID.idref
        # prop.Header.Message_ID.is_case_sensitive
        # prop.Header.Message_ID.is_defanged
        # prop.Header.Message_ID.is_obfuscated
        # prop.Header.Message_ID.obfuscation_algorithm_ref
        # prop.Header.Message_ID.observed_encoding
        # prop.Header.Message_ID.pattern_type
        # prop.Header.Message_ID.refanging_transform
        # prop.Header.Message_ID.refanging_transform_type
        # prop.Header.Message_ID.regex_syntax
        # prop.Header.Message_ID.trend
        # prop.Header.Message_ID.valueOf_

        # prop.Header.Sender IS SAME AS 'FROM'

        # prop.Header.Subject.appears_random
        # prop.Header.Subject.apply_condition
        # prop.Header.Subject.bit_mask
        # prop.Header.Subject.condition
        # prop.Header.Subject.datatype
        # prop.Header.Subject.defanging_algorithm_ref
        # prop.Header.Subject.delimiter
        # prop.Header.Subject.extensiontype_
        # prop.Header.Subject.has_changed
        # prop.Header.Subject.id
        # prop.Header.Subject.idref
        # prop.Header.Subject.is_case_sensitive
        # prop.Header.Subject.is_defanged
        # prop.Header.Subject.is_obfuscated
        # prop.Header.Subject.obfuscation_algorithm_ref
        # prop.Header.Subject.observed_encoding
        # prop.Header.Subject.pattern_type
        # prop.Header.Subject.refanging_transform
        # prop.Header.Subject.refanging_transform_type
        # prop.Header.Subject.regex_syntax
        # prop.Header.Subject.trend
        # prop.Header.Subject.valueOf_

        #Email Header has the following attributes: message_id, from, sender, subject
        emailHeader = prop.Header

        print "\tMessage id: " + emailHeader.Message_ID.valueOf_
        ObservableNode["MessageID"] = emailHeader.Message_ID.valueOf_

        if emailHeader.From:
            print "\t" + emailHeader.From.category + " (ObjType " + emailHeader.From.xsi_type + ") from " + emailHeader.From.Address_Value.valueOf_

            ObservableNode["From_Category"] = emailHeader.From.category
            ObservableNode["From_xsiType"] = emailHeader.From.xsi_type
            ObservableNode["From_AddressValue"] = emailHeader.From.Address_Value.valueOf_
        if emailHeader.Sender:
            print "\t" + emailHeader.Sender.category + " (ObjType: " + emailHeader.Sender.xsi_type + ") sent to " + emailHeader.Sender.Address_Value.valueOf_

            ObservableNode["Sender_Category"] = emailHeader.Sender.category
            ObservableNode["Sender_xsiType"] = emailHeader.Sender.xsi_type
            ObservableNode["Sender_AddressValue"] = emailHeader.Sender.Address_Value.valueOf_
        if emailHeader.Subject:
            print  "\tSubject (Apply condition: condition::delimiter: Value) " + emailHeader.Subject.apply_condition + ":" + \
                   emailHeader.Subject.condition + ":" + emailHeader.Subject.delimiter + ":" + ":" + emailHeader.Subject.valueOf_

            ObservableNode["Subject_ApplyCondition"] = emailHeader.Subject.apply_condition
            ObservableNode["Subject_Condition"] = emailHeader.Subject.condition
            ObservableNode["Subject_Delimiter"] = emailHeader.Subject.delimiter
            ObservableNode["Subject_Value"] = emailHeader.Subject.valueOf_

        #Email Attachments
        if prop.Attachments:
            emailAttachments = prop.Attachments.File
            print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            print "Email Attachments: "
            for i, attach in enumerate(emailAttachments):
                print "\t" + attach.object_reference
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
        print "WindowsRegistryKeyObjectType"+prop.xsi_type
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

        print "HandleWindowsRegistryKeyObjectType Win Registry Key Object"

    else:
        ObservableNode["xsiType"] = prop.xsi_type
        print "Handle "+ prop.xsi_type

    if obj.Object.Related_Objects:
        reltd = obj.Object.Related_Objects.Related_Object
        for reltdObj in reltd:
            ObservableNode["RelatedObjectID"] = reltdObj.id
            objRelated[obj.Object.id] = reltdObj.id
            if (type(reltdObj.Properties) == MutexObjectType):
                print "Handle Mutex Type Object"
                print " Properties : \n\t"+reltdObj.Properties.Name.apply_condition+"\n\t"
                print reltdObj.Properties.Name.condition+"\n\t"
                print reltdObj.Properties.Name.delimiter+"\n\t"
                print reltdObj.Properties.Name.valueOf_
            else:
                print "Related Object to be handled"

    headNode = stixGraph.find_one("HeaderNode", property_key="STIXFileID", property_value=StixFileID)
    rel = Relationship(headNode, "HeaderObservableLink", ObservableNode, STIXFileID=StixFileID,
                       connect="To make sure graph isn't disconnected")
    stixGraph.merge(rel)
    '''
    obsNode = stixGraph.find_one("ObservableNode", property_key="ObjectID", property_value=obj.id)
    if obsNode:
        relObs = Relationship(ObservableNode, "ObservableLink", obsNode, RelatedObservableID=obs.id_)
        stixGraph.merge(relObs)

        #relInd = Relationship(indNode,"IndicatorObservableLink", ObservableNode,  STIXFileID= StixFileID,connect="To make sure graph isn't disconnected")
        #stixGraph.merge(relInd)
    '''

def parse_ttps(ttp, kill_chains, kill_chain_phases, StixFileID):
    print "***********************************************TTPS*********************************************"
    for chain in ttp.kill_chains:
        kill_chains[chain.id_] = chain.name
        print "--"
        print "Name: " + chain.name
        print "Definer: " + chain.definer
        print "Kill Chain ID: " + chain.id_
        print "Number of Phases: " + chain.number_of_phases
        print "Reference: " + chain.reference

        desc = "Tactics,Techniques, Procedures. Contains kill chains that can be adopted when we encounter a threat.Connected to initNode"
        stixGraph.run("CREATE CONSTRAINT ON (n:TTPNode) ASSERT n.Name IS UNIQUE")
        TTPNode = Node("TTPNode", Description=desc, Name=chain.name, Definer=chain.definer, Reference=chain.reference,
                       NoOfPhases=chain.number_of_phases, ID=chain.id_, STIXFileID=StixFileID)
        rel = Relationship(init_node, "TTPGraphLink", TTPNode, connect="To make sure graph isn't disconnected")
        try:
            stixGraph.merge(rel)
        except ConstraintError:
            pass
        for phase in chain.kill_chain_phases:
            kill_chain_phases[phase.phase_id] = str(phase.name)
            print "Phases: [" + str(phase.phase_id) + "][" + str(phase.ordinality) + "] = " + str(phase.name)

            desc = "Each Kill Chain is defined in terms of phases in which we caught a particular threat."
            stixGraph.run("CREATE CONSTRAINT ON (n:KillChainPhaseNode) ASSERT n.Ordinality IS UNIQUE")
            KillChainPhaseNode = Node("KillChainPhaseNode", Description=desc, Ordinality=phase.ordinality,
                                      PhaseName=phase.name, ID=phase.phase_id, Chain_ID=chain.id_,
                                      STIXFileID=StixFileID)
            reln = Relationship(TTPNode, "TTPKillChainPhaseLink", KillChainPhaseNode, connect="Phases Of KillChain")

            try:
                stixGraph.merge(reln)
            except ConstraintError:
                pass


def parse_header(header, StixFileID):
    print "***********************************************HEADER*********************************************"
    head = header.to_obj()
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
    print "Title:\n\t" + head.Title
    for h in head.Description:
        desc = h.valueOf_
        print "Description:\n" + desc + "\n"
    try:
        head_date = head.Information_Source.Time.Produced_Time.valueOf_
        dt, tm = head_date.split("T", 1)
        year, month, day = dt.split("-", 2)
        tm2, ms = tm.split("+", 1)
        HH, MM, SS = tm2.split(":", 2)

        months = {"01": 'Jan', "02": 'Feb', "03": 'Mar', "04": 'Apr', "05": 'May', "06": 'Jun', "07": 'Jul',
                  "08": 'Aug', "09": 'Sep', "10": 'Oct', "11": 'Nov', "12": 'Dec'}
        print "Produced Date:" + day + " " + str(months.get(month)) + ", " + year
        print "Produced Time(24 HR):" + HH + ":" + MM + ":" + SS
    except AttributeError:
        head_date = DateTimeWithPrecision()  #Current Date ? Or just leave it Null ?

    #+"Produced Time Precision: "+ head.Information_Source.Time.Produced_Time.precision

    for pkInt in head.Package_Intent:
        print "XSI-TYPE: " + pkInt.xsi_type

    for mark in head.Handling.Marking:
        print "Marking:\n\t Controlled Structure: " + mark.Controlled_Structure
        for struc in mark.Marking_Structure:
            color = struc.color
            print "\t\tMarking Color: " + color
            #struc.id
            #struc.idref
            #struc.marking_model_name
            #struc.marking_model_ref
            print "\t\t XML-TYPE: " + struc.xml_type
            print "\t\tXML-Namespace: " + struc.xmlns
            print "\t\tXMLNS Prefix: " + struc.xmlns_prefix
    headNode = Node("HeaderNode", Title=head.Title, Description=desc, ProducedDate=dt, ProducedTime=tm,
                    PkgIntent_xsiType=pkInt.xsi_type, MarkingColor=color, xmlType=struc.xml_type,
                    xmlns=struc.xmlns, xmlnsPrefix=struc.xmlns_prefix, STIXFileID=StixFileID)
    rel = Relationship(init_node, "HeaderGraphLink", headNode, connect="To make sure graph isn't disconnected",
                       STIXFileID=StixFileID)
    stixGraph.merge(rel)


def parse_indicator(indicator, id, kill_chains, kill_chain_phases, indList, compInd, StixFileID):
    print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    if indicator.observables:
        parse_observables(indicator.observables, StixFileID)

    desc = "Indicators contains threat information and how to handle them within its observables, kill_chain phases etc.Connected to initNode"
    stixGraph.run("CREATE CONSTRAINT ON (n:IndicatorNode) ASSERT n.ID IS UNIQUE")
    IndicatorNode = Node("IndicatorNode", Description=desc, STIXFileID=StixFileID)
    rel = Relationship(init_node, "IndicatorGraphLink", IndicatorNode, connect="To make sure graph isn't disconnected",
                       STIXFileID=StixFileID)

    stixGraph.run("CREATE CONSTRAINT ON (n:AllowedIndicatorTypesNode) ASSERT n.ID IS UNIQUE")
    AllowedIndicatorTypesNode = Node("AllowedIndicatorTypesNode", Description="All allowed Indicator Types")

    if indicator.confidence: IndicatorNode["Confidence"] = indicator.confidence
    if indicator.handling: IndicatorNode["Handling"] = pprint(indicator.handling)
    if indicator.id_: IndicatorNode["ID"] = indicator.id_
    if indicator.idref: IndicatorNode["ID"] = indicator.idref
    if indicator.information_source: IndicatorNode["InformationSource"] = pprint(indicator.information_source)
    if indicator.likely_impact: IndicatorNode["LikelyImpact"] = pprint(indicator.likely_impact)
    if indicator.negate: IndicatorNode["IndicatorNegate"] = indicator.negate
    if indicator.producer: IndicatorNode["Producer"] = pprint(indicator.producer)
    if indicator.short_description: IndicatorNode["ShortDescription"] = pprint(indicator.short_descriptions)
    if indicator.suggested_coas: IndicatorNode["SuggestedCOA"] = pprint(indicator.suggested_coas)
    if indicator.timestamp: IndicatorNode["Timestamp"] = pprint(indicator.timestamp)
    if indicator.title: IndicatorNode["Title"] = indicator.title
    if indicator.version: IndicatorNode["Version"] = indicator.version
    if indicator.observable_composition_operator:
        IndicatorNode["CompositeIndicatorOperator"] = indicator.observable_composition_operator

    if indicator.description:
        if indicator.description.value: IndicatorNode["IndicatorDescription"] = indicator.description.value

    if indicator.indicator_types:
        for key in indicator.indicator_types:
            if key.value: IndicatorNode["IndicatorTypeValue"] = key.value
            if key.xsi_type: IndicatorNode["xsiType"] = key.xsi_type

            if key.TERM_ANONYMIZATION: AllowedIndicatorTypesNode["TERM_ANONYMIZATION"] = key.TERM_ANONYMIZATION
            if key.TERM_C2: AllowedIndicatorTypesNode["TERM_C2"] = key.TERM_C2
            if key.TERM_COMPROMISED_PKI_CERTIFICATE: AllowedIndicatorTypesNode[
                "TERM_COMPROMISED_PKI_CERTIFICATE"] = key.TERM_COMPROMISED_PKI_CERTIFICATE
            if key.TERM_DOMAIN_WATCHLIST: AllowedIndicatorTypesNode["TERM_DOMAIN_WATCHLIST"] = key.TERM_DOMAIN_WATCHLIST
            if key.TERM_EXFILTRATION: AllowedIndicatorTypesNode["TERM_EXFILTRATION"] = key.TERM_EXFILTRATION
            if key.TERM_FILE_HASH_WATCHLIST: AllowedIndicatorTypesNode[
                "TERM_FILE_HASH_WATCHLIST"] = key.TERM_FILE_HASH_WATCHLIST
            if key.TERM_HOST_CHARACTERISTICS: AllowedIndicatorTypesNode[
                "TERM_HOST_CHARACTERISTICS"] = key.TERM_HOST_CHARACTERISTICS
            if key.TERM_IMEI_WATCHLIST: AllowedIndicatorTypesNode["TERM_IMEI_WATCHLIST"] = key.TERM_IMEI_WATCHLIST
            if key.TERM_IMSI_WATCHLIST: AllowedIndicatorTypesNode["TERM_IMSI_WATCHLIST"] = key.TERM_IMSI_WATCHLIST
            if key.TERM_IP_WATCHLIST: AllowedIndicatorTypesNode["TERM_IP_WATCHLIST"] = key.TERM_IP_WATCHLIST
            if key.TERM_LOGIN_NAME: AllowedIndicatorTypesNode["TERM_LOGIN_NAME"] = key.TERM_ANONYMIZATION
            if key.TERM_MALICIOUS_EMAIL: AllowedIndicatorTypesNode["TERM_MALICIOUS_EMAIL"] = key.TERM_MALICIOUS_EMAIL
            if key.TERM_MALWARE_ARTIFACTS: AllowedIndicatorTypesNode[
                "TERM_MALWARE_ARTIFACTS"] = key.TERM_MALWARE_ARTIFACTS
            if key.TERM_URL_WATCHLIST: AllowedIndicatorTypesNode["TERM_URL_WATCHLIST"] = key.TERM_URL_WATCHLIST

    AllowedIndicatorTypesNode["ID"] = "OneCopy"
    relAllowInit = Relationship(init_node, "AllowedIndicatorTypesGraphLink", AllowedIndicatorTypesNode,
                                connect="Easy to find indicators of a particular type")
    try:
        stixGraph.merge(relAllowInit)
    except ConstraintError:
        pass

    if indicator.kill_chain_phases:
        for phase in indicator.kill_chain_phases:
            print "Kill Chain ID- " + phase.kill_chain_id
            print "\tKill Chain Name- " + phase.kill_chain_name
            print "Phase ID- " + phase.phase_id
            print "\tOrdinality- " + str(phase.ordinality)
            print "\tPhase Name- " + phase.name
            print "Kill Chain Name: " + kill_chains[phase.kill_chain_id]
            print "Phase[" + str(phase.ordinality) + "] = " + kill_chain_phases[phase.phase_id]
        ##########################################################################################################
            ######################CONNECT kill chain phase TO TTPNode's kill chain phsase ?

        phaseNode = stixGraph.find_one("KillChainPhaseNode", property_key="Ordinality", property_value=phase.ordinality)
        #stixGraph.run("CREATE CONSTRAINT ON (n:IndicatorNode) ASSERT n.ID IS UNIQUE")
        if phaseNode and IndicatorNode:
            relPhase = Relationship(phaseNode, "IndicatorKillChainPhaseLink", IndicatorNode, ID=indicator.id_, KillChainID=phase.kill_chain_id,
                                       PhaseID = phase.phase_id)
            try:
                stixGraph.merge(relPhase)
            except ConstraintError:
                pass
            except AttributeError:
                pass





    if indicator.sightings:
        IndicatorNode["SightingsCount"] = indicator.sightings.sightings_count
        for s in indicator.sightings:
            if s.timestamp and s.timestamp_precision:
                IndicatorNode["SightingsTimestamp"] = pprint(s.timestamp)
                IndicatorNode["SightingsTimestampPrecision"] = str(s.timestamp_precision)
                print "Timestamp " + str(s.timestamp) + " with precision upto " + s.timestamp_precision
            if s.confidence: IndicatorNode["SightingsConfidence"] = s.confidence
            if s.description: IndicatorNode["SightingsDescription"] = s.description
            if s.reference: IndicatorNode["SightingsReference"] = s.reference
            if s.related_observables: IndicatorNode["SightingsRelatedObservables"] = pprint(s.related_observables)
            if s.source: IndicatorNode["SightingsSource"] = pprint(s.source)

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

    for ind in indList:
        compIndNode = stixGraph.find_one("IndicatorNode", property_key="ID", property_value=compInd)
        indNode = stixGraph.find_one("IndicatorNode", property_key="ID", property_value= ind)
        if compIndNode and indNode:
            relInd = Relationship(compInd, "CompositionIndicatorLink", indNode, CompositionOperator=indicator.observable_composition_operator)
            try:
                stixGraph.merge(relInd)
            except ConstraintError:
                pass
            except AttributeError:
                pass

    stixGraph.merge(rel)

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
    indList = []
    for indicator in indicators:
        if (indicator.composite_indicator_expression):
            compInd = str(indicator.id_)
        else:
            indList.append(str(indicator.id_))

    for indicator in indicators:
        parse_indicator(indicator, indicator.id_, kill_chains, kill_chain_phases, indList, compInd, StixFileID)

def print_parsed_data(pkg):
    kill_chains = {}
    kill_chain_phases = {}

    if pkg.campaigns:
        logging.info('Should I create Null Values to make it STIX complaint?')

    if pkg.courses_of_action:
        logging.info('Should I create Null Values to make it STIX complaint?')

    if pkg.exploit_targets:
        logging.info('Should I create Null Values to make it STIX complaint?')

    if pkg.incidents:
        logging.info('Should I create Null Values to make it STIX complaint?')

    if pkg.related_packages:
        logging.info('Should I create Null Values to make it STIX complaint?')

    if pkg.reports:
        logging.info('Should I create Null Values to make it STIX complaint?')

    if pkg.threat_actors:
        logging.info('Should I create Null Values to make it STIX complaint?')

    if pkg.stix_header:
        parse_header(pkg.stix_header, pkg._id)

    if pkg.ttps:
        parse_ttps(pkg.ttps, kill_chains, kill_chain_phases, pkg._id)

    if pkg.observables:
        parse_observables(pkg.observables.observables, pkg._id)

    if pkg.indicators:
        parse_indicators(pkg.indicators, kill_chains, kill_chain_phases, pkg._id)

        #ts = time.mktime, (pkg.timestamp.timetuple()) if pkg.timestamp else int(time.mktime(time.gmtime()))


def parse_file(myfile):
    f = open(myfile)
    #parse the input file
    logging.info('Parsing input file '+str(f))
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
    #test_file('../TEST/1.xml')
    #test_file('../TEST/8.xml')
    test_files()
    #test_GreenIOC()


if __name__ == '__main__':
    main()

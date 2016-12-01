__author__ = 'apoorva'
from py2neo.database import Record
from graph_stix.config import stixGraph
from pandas import DataFrame as df

def getIPInfo(ipaddr):

    result = df(stixGraph.run("MATCH (a:ObservableNode) WHERE a.AddressValue={x} RETURN a.ObservableID, a.ObjectID, a.IndicatorID",
                              x=ipaddr).data()).to_html()
    return result

def getURIinfo(uri):
    recs = stixGraph.run("MATCH (a:ObservableNode) WHERE a.Value={x} RETURN a.ObservableID, a.ObjectID, a.IndicatorID",x=str(uri)).data()
    '''
    res= res+recs
    if recs.forward():
        recs = stixGraph.run("MATCH (a:ObservableNode) WHERE a.Value={x} RETURN a.ObservableID, a.ObjectID, a.IndicatorID",x=str(uri))
        res= res+recs
    '''
    result = df(recs)
    return result.to_html()

def getMutexInfo(mutex):
    recs = stixGraph.run("MATCH (a:ObservableNode) WHERE a.MutexValue={x} RETURN a.ObservableID, a.ObjectID, a.IndicatorID",x=str(mutex)).data()
    result = df(recs).to_html()
    return result

def getFileInfo(file):
    recs = stixGraph.run("MATCH (a:ObservableNode) WHERE EXISTS(a.FileHash) RETURN a.ObservableID, a.ObjectID, a.IndicatorID, a.FileHash, a.SizeInBytes").data()

    for r in recs:
        Hashes = eval(r["a.FileHash"])
        for key in Hashes:
            f = Hashes[key]
            if f== file:
                res = df(stixGraph.run("MATCH (a:ObservableNode) WHERE a.ObservableID={x} RETURN a.ObservableID, a.ObjectID, a.IndicatorID, a.FileHash, a.SizeInBytes",
                 x= r["a.ObservableID"]).data())
                break

    return res.to_html()
import web
import model
urls = (
    '/', 'Threat',
    '/threat', 'Threat'
)
web.config.debug = True
app = web.application(urls, globals())

class Threat(object):
    def __init__(self):
        self.render = web.template.render('templates/', base="layout")
    def GET(self):
        form = web.input(threatIDRealWorld=None, threatVal=None)
        if form.threatIDRealWorld == None and form.threatVal == None:
            input = None
            result=None
        else:
            input = "%s: %s" % (form.threatIDRealWorld, form.threatVal)
            if form.threatIDRealWorld == 'IPAddress':
                result = model.getIPInfo(form.threatVal)
            elif form.threatIDRealWorld == 'Mutex':
                result = model.getEmailInfo(form.threatVal)
            elif form.threatIDRealWorld == 'File':
                result = model.getFileInfo(form.threatVal)
            elif form.threatIDRealWorld == 'URI':
                result = model.getURIinfo(form.threatVal)

        return self.render.threatInputForm(threatInput=input, result=result)

    def POST(self):
        form = web.input(threatIDRealWorld=None, threatVal=None)
        if form.threatIDRealWorld == None and form.threatVal == None:
            input = None
            result=None
        else:
            input = "%s: %s" % (form.threatIDRealWorld, form.threatVal)
            if form.threatIDRealWorld == 'IPAddress':
                result = model.getIPInfo(form.threatVal)
            elif form.threatIDRealWorld == 'Mutex':
                result = model.getMutexInfo(form.threatVal)
            elif form.threatIDRealWorld == 'File':
                result = model.getFileInfo(form.threatVal)
            elif form.threatIDRealWorld == 'URI':
                result = model.getURIinfo(form.threatVal)

        return self.render.threatInputForm(threatInput=input, result=result)

class Index(object):
    def __init__(self):
        self.render = web.template.render('templates/', base="layout")

    def GET(self):
        form = web.input(name="Nobody")
        result = None
        input = "Hello, %s" % form.name
        return self.render.index(threatInput=input, result=result)

    def POST(self):
        form = web.input(name="Nobody")
        result = None
        input = "Hello, %s" % form.name
        return self.render.index(threatInput=input, result=result)


if __name__ == "__main__":
    app.run()

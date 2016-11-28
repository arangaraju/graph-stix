import web

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
            greeting = None
        else:
            greeting = "%s, %s" % (form.threatIDRealWorld, form.threatVal)
        result = ['4', '2', '3']
        return self.render.threatInputForm(greeting=greeting, result=result)

    def POST(self):
        form = web.input(threatIDRealWorld="ids", threatVal="vals")
        greeting = "%s, %s" % (form.threatIDRealWorld, form.threatVal)
        result = ['1', '2', '3']
        return self.render.threatInputForm(greeting=greeting, result=result)



class Index(object):
    def __init__(self):
        self.render = web.template.render('templates/', base="layout")

    def GET(self):
        form = web.input(name="Nobody")
        result = ['1', '2', '3']
        greeting = "Hello, %s" % form.name
        return self.render.index(greeting=greeting, result=result)

    def POST(self):
        return "post"

        '''
        form = web.input(name="Nobody", greet="Hello")
        greeting = "%s, %s" % (form.greet, form.name)
        title = ['1', '2', '3']
        return self.render.index(greeting=greeting, title=title)

        '''


if __name__ == "__main__":
    app.run()

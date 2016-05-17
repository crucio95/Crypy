from Tkinter import *
from tkFileDialog import askopenfilename
from module import aes, xor

radice = Tk()
radice.wm_title("Crypy")

class Grafica:
	def __init__(self, radice):
		self.radice = radice
		self.radice.geometry("500x150")
		self.box = Frame(radice)
		self.box.pack()
		
		self.file_opt = options = {}
		options['defaultextension'] = '.txt'
		options['filetypes'] = [('all files', '.*'), ('text files', '.txt')]
		options['initialdir'] = 'C:\\'
		options['parent'] = radice
		options['title'] = 'Path to File'
		
		self.v = StringVar()
		self.v.set("XOR")
		self.x = BooleanVar()
		self.x.set(1)
		self.password = StringVar()
			
		MODES = [
		("XOR", self.v, "XOR", LEFT),
		("AES", self.v, "AES", LEFT),
		("Encrypt", self.x, 1, RIGHT),
		("Decrypt", self.x, 0, RIGHT),
		]		
	
		self.pathrun = Frame(self.box)
		self.pathrun.pack(fill = BOTH, expand = YES)
		self.option = Frame(self.box, height = 6)
		self.option.pack(side = TOP, fill = BOTH)
		self.bottom = Frame(self.box)
		self.bottom.pack(side = BOTTOM, fill = BOTH)

		self.path = Label(self.pathrun, text = "PATH", relief = GROOVE)
		self.path.config(width = 50, height = 2, background = "white")
		self.path.pack(side = LEFT)
		self.browse = Button(self.pathrun, text = "Browse", command = self.Browse, width = 15, height = 2).pack(side = LEFT)
		
		for testo, var, valore, giust in MODES:
			self.radio = Radiobutton(self.option, text = testo, variable = var, value = valore, indicatoron = 1)
			self.radio.pack(side = giust)
		self.desc = Label(self.option, text = "Enter a Password").pack(anchor = CENTER)
		self.pas = Entry(self.option, textvariable = self.password, show = "*", relief = GROOVE).pack(anchor = CENTER)
		self.runit = Button(self.bottom, text = "RUN IT", width = 40, height = 3, command = main).pack(anchor = CENTER, pady = "5m")
	def Browse(self):
		file = askopenfilename(**self.file_opt)
		self.path.config(text = file)
		self.path.pack()

magicwrd = "magicwrd"
def Datas(path):
	try:
		file = open(path, mode='r')
		data = file.read()
		datafix = data.strip()
	except Exception as e:    #manage exceptions
		print("[*] Wrong path or bad syntax for input, %s." % e)
		sys.exit(0)
	return datafix

def main():
	global magicwrd
	path = grafica.path["text"]
	if grafica.v.get() == "XOR":
		if grafica.x.get():
			pasb = xor.binIt(grafica.password.get())
			data = xor.binIt(Datas(path))
			xor.outPutter(path + "crypt", xor.cryPy(pasb, data, magicwrd))
		else:
			pasb = xor.binIt(grafica.password.get())
			data = Datas(path)
			xor.outPutter(path[:(len(path)-5)], xor.decryPy(pasb, data, magicwrd))
	else:
		if grafica.x.get():
			aes.encrypt(path, grafica.password.get())
		else:
			aes.decrypt(path, grafica.password.get())
	

grafica = Grafica(radice)
radice.mainloop()
from Tkinter import *
from tkFileDialog import askopenfilename



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
		
		v = StringVar()
		v.set("XOR")
		x = IntVar()
		x.set(1)
		password = StringVar()
			
		MODES = [
		("XOR", v, "XOR", LEFT),
		("AES", v, "AES", LEFT),
		("Encrypt", x, 1, RIGHT),
		("Decrypt", x, 0, RIGHT),
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
		self.pas = Entry(self.option, textvariable = password, show = "*", relief = GROOVE).pack(anchor = CENTER)
		self.runit = Button(self.bottom, text = "RUN IT", width = 40, height = 3).pack(anchor = CENTER, pady = "5m")
	def Browse(self):
		file = askopenfilename(**self.file_opt)
		self.path.config(text = file)
		self.path.pack()


radice = Tk()
radice.wm_title("Crypy")
grafica = Grafica(radice)
radice.mainloop()
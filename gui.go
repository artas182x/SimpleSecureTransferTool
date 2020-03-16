package main

import (
	"os"
	"strconv"

	"github.com/gotk3/gotk3/gtk"
)

func initWindow(title string) (window *gtk.Window) {
	gtk.Init(nil)
	window, _ = gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	window.SetTitle(title)
	window.Connect("destroy", func() {
		gtk.MainQuit()
	})
	return window
}

func getTextBox(callback interface{}) *gtk.Entry {
	textBox, _ := gtk.EntryNew()
	textBox.Connect("activate", callback)
	textBox.GrabFocus()
	return textBox
}

func getPasswordBox(callback interface{}) *gtk.Entry {
	passwordBox := getTextBox(callback)
	passwordBox.SetVisibility(false)
	return passwordBox
}

func getGridLayout() *gtk.Grid {
	gridLayout, _ := gtk.GridNew()
	gridLayout.SetVAlign(gtk.ALIGN_CENTER)
	gridLayout.SetHAlign(gtk.ALIGN_CENTER)
	return gridLayout
}

func getButton(label string, callback func(*gtk.Button)) *gtk.Button {
	button, _ := gtk.ButtonNewWithLabel(label)
	button.Connect("clicked", callback)
	return button
}

func getPasswordLayout(title string, callback func(string, *gtk.Grid, *gtk.Label)) *gtk.Grid {
	layout := getGridLayout()
	titleLabel, _ := gtk.LabelNew(title)
	passwordLabel, _ := gtk.LabelNew("Password: ")
	errorLabel, _ := gtk.LabelNew("")
	passwordCallback := func(passwordBox *gtk.Entry) {
		text, _ := passwordBox.GetText()
		callback(text, layout, errorLabel)
	}
	passwordBox := getPasswordBox(passwordCallback)
	enterCallback := func(button *gtk.Button) {
		text, _ := passwordBox.GetText()
		callback(text, layout, errorLabel)
	}
	enterButton := getButton("Enter", enterCallback)
	emptyLabel, _ := gtk.LabelNew("")
	layout.Attach(titleLabel, 0, 0, 2, 1)
	layout.Attach(emptyLabel, 0, 1, 2, 1)
	layout.Attach(passwordLabel, 0, 2, 1, 1)
	layout.Attach(passwordBox, 1, 2, 1, 1)
	layout.Attach(enterButton, 0, 3, 2, 1)
	layout.Attach(errorLabel, 0, 4, 2, 1)
	return layout
}

func isPasswordSet() bool {
	_, err := os.Stat("config")
	return !os.IsNotExist(err)
}

func getLoginLayout(loginCallback func()) *gtk.Grid {
	callback := func(password string, layout *gtk.Grid, errorLabel *gtk.Label) {
		encryptor := EncryptedMessageHandler(32, CBC)
		encryptor.LoadKeys("config", password)
		layout.Destroy()
		loginCallback()
	}
	return getPasswordLayout("Login", callback)
}

func getRegisterLayout(registerCallback func()) *gtk.Grid {
	callback := func(password string, layout *gtk.Grid, errorLabel *gtk.Label) {
		if len(password) <= 0 {
			errorLabel.SetMarkup("<span foreground='red'>Password must be longer than 0</span>")
		} else {
			println("Registered: " + password)
			os.MkdirAll("config", os.ModePerm)
			encryptor := EncryptedMessageHandler(32, CBC)
			err := encryptor.CreateKeys("config", password)
			if err != nil {
				println(err.Error())
			} else {
				layout.Destroy()
				registerCallback()
			}
		}
	}
	return getPasswordLayout("Enter new password", callback)
}

func getConnectLayout(callback func(string)) *gtk.Grid {
	layout := getGridLayout()
	titleLabel, _ := gtk.LabelNew("Targets IP address: ")
	addressCallback := func(textBox *gtk.Entry) {
		text, _ := textBox.GetText()
		callback(text)
		layout.Destroy()
	}
	addressBox := getTextBox(addressCallback)
	enterCallback := func(button *gtk.Button) {
		text, _ := addressBox.GetText()
		callback(text)
		layout.Destroy()
	}
	enterButton := getButton("Enter", enterCallback)
	layout.Attach(titleLabel, 0, 0, 1, 1)
	layout.Attach(addressBox, 1, 0, 1, 1)
	layout.Attach(enterButton, 0, 1, 2, 1)
	return layout
}

func getBlockCipherLayout(cipherChoosenCallback func(string)) *gtk.Grid {
	layout := getGridLayout()
	// titleLabel, _ := gtk.LabelNew("Choose ")
	choices := [4]string{"ECB", "CBC", "CFB", "OFB"}
	choicesBox, _ := gtk.ComboBoxTextNew()
	for i := 0; i < len(choices); i++ {
		choicesBox.AppendText(choices[i])
	}
	choicesBox.SetActive(0)
	selectButton := getButton("Select", func(button *gtk.Button) {
		layout.Destroy()
		cipherChoosenCallback(choicesBox.GetActiveText())
	})
	layout.Add(choicesBox)
	layout.Add(selectButton)
	return layout
}

// func getTextAppLayout() *gtk.G

//RunGUI starts gui of the application
func RunGUI() {
	window := initWindow("SimpleSecureTransferTool")
	window.SetDefaultSize(1920/2, 1080/2)
	mainLayout := getGridLayout()
	addressChoosenCallback := func(address string) {
		println(address)
		textTagTable, _ := gtk.TextTagTableNew()
		textBuffer, _ := gtk.TextBufferNew(textTagTable)
		textView, _ := gtk.TextViewNewWithBuffer(textBuffer)
		textView.SetEditable(false)
		iter := textBuffer.GetEndIter()
		for i := 0; i < 5; i++ {
			textBuffer.Insert(iter, "Test"+strconv.Itoa(i)+"\n")
		}
		pane, _ := gtk.PanedNew(gtk.ORIENTATION_HORIZONTAL)
		pane.Pack1(textView, true, true)
		label, _ := gtk.LabelNew("AAAAAAAAAAA")
		pane.Pack2(label, true, true)
		mainLayout.Add(pane)
		window.ShowAll()
	}
	passwordCallback := func() {
		println("Logged in")
		// mainLayout.Add(getBlockCipherLayout(blockCipherChoosenCallback))
		mainLayout.Add(getConnectLayout(addressChoosenCallback))
		window.ShowAll()
	}
	if isPasswordSet() {
		mainLayout.Add(getLoginLayout(passwordCallback))
	} else {
		mainLayout.Add(getRegisterLayout(passwordCallback))
	}
	window.Add(mainLayout)
	window.SetPosition(gtk.WIN_POS_CENTER)
	window.ShowAll()
	gtk.Main()
}

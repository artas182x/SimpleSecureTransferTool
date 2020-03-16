package main

import (
	"os"

	"github.com/gotk3/gotk3/gtk"
)

//GUIApp is structure used for running gui of application and handling messages
type GUIApp struct {
	textBuffer *gtk.EntryBuffer
	enryptor   EncMess
	netClient  NetClient
}

//GUIAppNew return new instance of application
func GUIAppNew(port int32) (app GUIApp) {
	app.enryptor = EncryptedMessageHandler(32, CBC)
	app.netClient = NetClientInit(port, app.enryptor)
	go app.netClient.NetclientListen()
	return
}

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
	passwordLayout := getPasswordLayout("Login", callback)
	newKeysCallback := func(button *gtk.Button) {
		encryptor := EncryptedMessageHandler(32, CBC)
		os.RemoveAll("config")
		passwordBox, _ := passwordLayout.GetChildAt(1, 2)
		password, _ := passwordBox.GetProperty("text")
		os.MkdirAll("config", os.ModePerm)
		err := encryptor.CreateKeys("config", string(password.(string)))
		if err != nil {
			println(err.Error())
		} else {
			passwordLayout.Destroy()
			loginCallback()
		}
	}
	newKeysButton := getButton("Generate new keys", newKeysCallback)
	passwordLayout.Attach(newKeysButton, 0, 4, 2, 1)
	return passwordLayout
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
	}
	addressBox := getTextBox(addressCallback)
	enterCallback := func(button *gtk.Button) {
		text, _ := addressBox.GetText()
		callback(text)
	}
	enterButton := getButton("Connect", enterCallback)
	layout.Attach(titleLabel, 0, 0, 1, 1)
	layout.Attach(addressBox, 1, 0, 1, 1)
	layout.Attach(enterButton, 0, 1, 2, 1)
	return layout
}

func getBlockCipherLayout(cipherChoosenCallback func(string)) *gtk.Grid {
	layout := getGridLayout()
	titleLabel, _ := gtk.LabelNew("Choose algorithm: ")
	choices := [4]string{"ECB", "CBC", "CFB", "OFB"}
	choicesBox, _ := gtk.ComboBoxTextNew()
	for i := 0; i < len(choices); i++ {
		choicesBox.AppendText(choices[i])
	}
	choicesBox.SetActive(0)
	selectButton := getButton("Select", func(button *gtk.Button) {
		cipherChoosenCallback(choicesBox.GetActiveText())
	})
	layout.Attach(titleLabel, 0, 0, 2, 1)
	layout.Attach(choicesBox, 0, 1, 1, 1)
	layout.Attach(selectButton, 1, 1, 1, 1)
	return layout
}

func getMessagesLayout(textWrittenCallback func(text string)) *gtk.Grid {
	scrolledWindow, _ := gtk.ScrolledWindowNew(nil, nil)
	scrolledWindow.SetSizeRequest(1920/4, 1080/3)
	layout := getGridLayout()
	textTagTable, _ := gtk.TextTagTableNew()
	textBuffer, _ := gtk.TextBufferNew(textTagTable)
	textView, _ := gtk.TextViewNewWithBuffer(textBuffer)
	textView.SetEditable(false)
	textView.SetCanFocus(false)
	textView.SetWrapMode(gtk.WrapMode(1))
	iter := textBuffer.GetEndIter()
	titleLabel, _ := gtk.LabelNew("Messages: ")
	textBoxCallback := func(textBox *gtk.Entry) {
		text, _ := textBox.GetText()
		textBuffer.Insert(iter, "You: "+text+"\n")
		textBox.SetText("")
		textWrittenCallback(text)
	}
	textInput := getTextBox(textBoxCallback)
	promptLabel, _ := gtk.LabelNew("Write message: ")
	enterButtonCallback := func(button *gtk.Button) {
		text, _ := textInput.GetText()
		textBuffer.Insert(iter, "You: "+text+"\n")
		textInput.SetText("")
		textWrittenCallback(text)
	}
	enterButton := getButton("Send", enterButtonCallback)
	scrolledWindow.Add(textView)
	layout.Attach(titleLabel, 0, 0, 3, 1)
	layout.Attach(scrolledWindow, 0, 1, 3, 1)
	layout.Attach(promptLabel, 0, 2, 1, 1)
	layout.Attach(textInput, 1, 2, 1, 1)
	layout.Attach(enterButton, 2, 2, 1, 1)
	return layout
}

func getConfigLayout(cipherChoosenCallback func(string), addressChoosenCallback func(string)) (*gtk.Grid, *gtk.Label) {
	layout := getGridLayout()
	addressLayout := getConnectLayout(addressChoosenCallback)
	cipherLayout := getBlockCipherLayout(cipherChoosenCallback)
	connectedLabel, _ := gtk.LabelNew("Connected: ")
	statusLabel, _ := gtk.LabelNew("No")
	separator, _ := gtk.SeparatorNew(gtk.ORIENTATION_HORIZONTAL)
	layout.Attach(connectedLabel, 0, 0, 1, 1)
	layout.Attach(statusLabel, 1, 0, 1, 1)
	layout.Attach(separator, 0, 1, 2, 1)
	layout.Attach(addressLayout, 0, 2, 2, 1)
	layout.Attach(separator, 0, 3, 2, 1)
	layout.Attach(cipherLayout, 0, 4, 2, 1)
	return layout, statusLabel
}

//RunGUI starts gui of the application
func (app *GUIApp) RunGUI() {
	window := initWindow("SimpleSecureTransferTool")
	window.SetDefaultSize(1920/2, 1080/2)
	var connectionStatusLabel *gtk.Label = nil
	mainLayout := getGridLayout()
	cipherChoosenCallback := func(cipher string) {
		switch cipher {
		case "ECB":
			app.enryptor.cipherMode = ECB
			break
		case "CBC":
			app.enryptor.cipherMode = CBC
			break
		case "CFB":
			app.enryptor.cipherMode = CFB
			break
		case "OFB":
			app.enryptor.cipherMode = OFB
			break
		}
		app.netClient.SendConnectionProperties()
		println("Sending new cipher: ", cipher)
	}
	messageWrittenCallback := func(message string) {
		app.netClient.SendTextMessage(message)
		println("sending message: ", message)
	}
	addressChoosenCallback := func(address string) {
		err := app.netClient.SendHello(address)
		if err != nil {
			println("not connected")
			app.netClient.connected = false
			connectionStatusLabel.SetText("No")
		} else {
			println("connected")
			app.netClient.connected = true
			connectionStatusLabel.SetText("Yes")
		}
	}
	passwordCallback := func() {
		pane, _ := gtk.PanedNew(gtk.ORIENTATION_HORIZONTAL)
		leftLayout := getMessagesLayout(messageWrittenCallback)
		pane.Pack1(leftLayout, true, true)
		rightLayout, statusLabel := getConfigLayout(cipherChoosenCallback, addressChoosenCallback)
		connectionStatusLabel = statusLabel
		pane.Pack2(rightLayout, true, true)
		mainLayout.Add(pane)
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

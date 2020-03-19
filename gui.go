package main

import (
	"log"
	"os"

	"github.com/gotk3/gotk3/gtk"
)

//GUIApp is structure used for running gui of application and handling messages
type GUIApp struct {
	textBuffer            *gtk.TextBuffer
	textIter              *gtk.TextIter
	connectionStatusLabel *gtk.Label
	cipherChoiceBox       *gtk.ComboBoxText
	addressBox            *gtk.Entry
	progressBar           *gtk.ProgressBar
	newFileLabel          *gtk.Label
	port                  int32
	encryptor             EncMess
	netClient             NetClient
}

//GUIAppNew return new instance of application
func GUIAppNew(port int32) (app GUIApp) {
	app.port = port
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

func getLoginLayout(loginCallback func(EncMess)) *gtk.Grid {
	callback := func(password string, layout *gtk.Grid, errorLabel *gtk.Label) {
		encryptor := EncryptedMessageHandler(32, CBC)
		encryptor.LoadKeys("config", password)
		layout.Destroy()
		loginCallback(encryptor)
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
			loginCallback(encryptor)
		}
	}
	newKeysButton := getButton("Generate new keys", newKeysCallback)
	passwordLayout.Attach(newKeysButton, 0, 4, 2, 1)
	return passwordLayout
}

func getRegisterLayout(registerCallback func(mess EncMess)) *gtk.Grid {
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
				registerCallback(encryptor)
			}
		}
	}
	return getPasswordLayout("Enter new password", callback)
}

func getConnectLayout(callback func(string)) (*gtk.Grid, *gtk.Entry) {
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
	return layout, addressBox
}

func getBlockCipherLayout(cipherChosenCallback func(string)) (*gtk.Grid, *gtk.ComboBoxText) {
	layout := getGridLayout()
	titleLabel, _ := gtk.LabelNew("Choose algorithm: ")
	choices := [4]string{"ECB", "CBC", "CFB", "OFB"}
	choicesBox, _ := gtk.ComboBoxTextNew()
	for i := 0; i < len(choices); i++ {
		choicesBox.AppendText(choices[i])
	}
	choicesBox.SetActive(1)
	selectButton := getButton("Select", func(button *gtk.Button) {
		cipherChosenCallback(choicesBox.GetActiveText())
	})
	layout.Attach(titleLabel, 0, 0, 2, 1)
	layout.Attach(choicesBox, 0, 1, 1, 1)
	layout.Attach(selectButton, 1, 1, 1, 1)
	return layout, choicesBox
}

func getFileTransferLayout(window *gtk.Window, sendButtonPressedCallback func(*gtk.FileChooserNativeDialog)) (*gtk.Grid, *gtk.ProgressBar, *gtk.Label) {
	layout := getGridLayout()
	titleLabel, _ := gtk.LabelNew("Send File: ")
	progressBar, _ := gtk.ProgressBarNew()
	styleContext, _ := progressBar.GetStyleContext()
	mRefProvider, _ := gtk.CssProviderNew()
	if err := mRefProvider.LoadFromPath("styles.css"); err != nil {
		log.Println(err)
	}
	styleContext.AddProvider(mRefProvider, gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
	filePicker, _ := gtk.FileChooserNativeDialogNew("Choose file to send", window, gtk.FILE_CHOOSER_ACTION_OPEN, "Accept", "Cancel")
	chooseFileButtonPressedCallback := func(button *gtk.Button) {
		filePicker.Run()
	}
	chooseFileButton := getButton("Choose File", chooseFileButtonPressedCallback)
	newFileLabel, _ := gtk.LabelNew("")
	sendFileButton := getButton("Send", func(button *gtk.Button) {
		sendButtonPressedCallback(filePicker)
	})
	layout.Attach(titleLabel, 0, 0, 2, 1)
	layout.Attach(chooseFileButton, 0, 1, 2, 1)
	layout.Attach(progressBar, 0, 2, 1, 1)
	layout.Attach(sendFileButton, 1, 2, 1, 1)
	return layout, progressBar, newFileLabel
}

func getMessagesLayout(textWrittenCallback func(text string)) (*gtk.Grid, *gtk.TextBuffer, *gtk.TextIter) {
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
	return layout, textBuffer, iter
}

func getConfigLayout(cipherChosenCallback func(string), addressChosenCallback func(string), window *gtk.Window, sendFileCallback func(dialog *gtk.FileChooserNativeDialog)) (*gtk.Grid, *gtk.Label, *gtk.Entry, *gtk.ComboBoxText, *gtk.ProgressBar) {
	layout := getGridLayout()
	addressLayout, addressTextBox := getConnectLayout(addressChosenCallback)
	cipherLayout, cipherChoiceBox := getBlockCipherLayout(cipherChosenCallback)
	connectedLabel, _ := gtk.LabelNew("Connected: ")
	statusLabel, _ := gtk.LabelNew("No")
	separator, _ := gtk.SeparatorNew(gtk.ORIENTATION_HORIZONTAL)
	fileTransferLayout, progressBar, _ := getFileTransferLayout(window, sendFileCallback)
	layout.Attach(connectedLabel, 0, 0, 1, 1)
	layout.Attach(statusLabel, 1, 0, 1, 1)
	layout.Attach(separator, 0, 1, 2, 1)
	layout.Attach(addressLayout, 0, 2, 2, 1)
	layout.Attach(separator, 0, 3, 2, 1)
	layout.Attach(cipherLayout, 0, 4, 2, 1)
	layout.Attach(separator, 0, 5, 2, 1)
	layout.Attach(fileTransferLayout, 0, 6, 2, 2)
	return layout, statusLabel, addressTextBox, cipherChoiceBox, progressBar
}

func showErrorPopup(window *gtk.Window, err error) {
	popup := gtk.MessageDialogNew(window, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, err.Error())
	popup.Connect("response", func() {
		popup.Destroy()
	})
	popup.Run()
}

func (app *GUIApp) UpdateUploadProgressBar(value float64) {
	app.progressBar.SetFraction(value)
}

//UpdateCipherMode updates cipher mode choice box
func (app *GUIApp) UpdateCipherMode() {
	app.cipherChoiceBox.SetActive(int(app.netClient.GetCipher()))
}

//ShowMessage shows user message in the messaging box
func (app *GUIApp) ShowMessage(message string) {
	app.textBuffer.Insert(app.textIter, "Friend: "+message)
}

//ChangeAddress sets showed address to value
func (app *GUIApp) ChangeAddress(address string) {
	app.addressBox.SetText(address)
}

//SetConnected sets label to Yes if given true
func (app *GUIApp) SetConnected(connected bool) {
	if connected {
		app.connectionStatusLabel.SetText("Yes")
	} else {
		app.connectionStatusLabel.SetText("No")
	}
}

//RunGUI starts gui of the application
func (app *GUIApp) RunGUI() {
	window := initWindow("SimpleSecureTransferTool")
	window.SetDefaultSize(1920/2, 1080/2)
	mainLayout := getGridLayout()
	cipherChosenCallback := func(cipher string) {
		switch cipher {
		case "ECB":
			app.netClient.SetCipher(ECB)
			break
		case "CBC":
			app.netClient.SetCipher(CBC)
			break
		case "CFB":
			app.netClient.SetCipher(CFB)
			break
		case "OFB":
			app.netClient.SetCipher(OFB)
			break
		}
		err := app.netClient.SendConnectionProperties()
		if err != nil {
			println(err.Error())
		}
		println("Sending new cipher: ", cipher)
	}
	messageWrittenCallback := func(message string) {
		err := app.netClient.SendTextMessage(message)
		if err != nil {
			println(err.Error())
		}
		println("sending message: ", message)
	}
	addressChosenCallback := func(address string) {
		err := app.netClient.SendHello(address)
		if err != nil {
			println("not connected")
			app.netClient.connected = false
			app.connectionStatusLabel.SetText("No")
		} else {
			println("connected")
			app.netClient.connected = true
			app.connectionStatusLabel.SetText("Yes")
		}
	}
	passwordCallback := func(encryptor EncMess) {
		leftLayout, textBuffer, textIter := getMessagesLayout(messageWrittenCallback)
		app.textBuffer = textBuffer
		app.textIter = textIter
		app.encryptor = encryptor
		app.netClient = NetClientInit(app.port, app.encryptor)
		go app.netClient.NetClientListen(app)
		pane, _ := gtk.PanedNew(gtk.ORIENTATION_HORIZONTAL)
		pane.Pack1(leftLayout, true, true)
		sendFileCallback := func(dialog *gtk.FileChooserNativeDialog) {
			file, err := os.Open(dialog.GetFilename())
			if err != nil {
				showErrorPopup(window, err)
			} else {
				go app.netClient.SendFile(file, app)
			}
		}
		rightLayout, statusLabel, addressBox, cipherChoiceBox, progressBar := getConfigLayout(cipherChosenCallback, addressChosenCallback, window, sendFileCallback)
		app.connectionStatusLabel = statusLabel
		app.addressBox = addressBox
		app.cipherChoiceBox = cipherChoiceBox
		app.progressBar = progressBar
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

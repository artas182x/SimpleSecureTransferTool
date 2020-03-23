package main

import (
	"os"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

//GUIApp is structure used for running gui of application and handling messages
type GUIApp struct {
	//Main Window
	mainWindow *gtk.Window
	mainLayout *gtk.Grid

	//Messaging Layout
	messageTextBuffer *gtk.TextBuffer
	messageTextIter   *gtk.TextIter

	//Connection Layout
	connectionStatusLabel *gtk.Label
	addressBox            *gtk.Entry

	//CipherChoice Layout
	cipherChoiceBox *gtk.ComboBoxText

	//FileUpload Layout
	uploadProgressBar  *gtk.ProgressBar
	uploadTimeLabel    *gtk.Label
	encryptProgressBar *gtk.ProgressBar
	encryptTimeLabel   *gtk.Label

	//FileDownload Layout
	newFileLabel *gtk.Label

	//NetClient
	port      int32
	encryptor EncMess
	netClient NetClient
}

//GUIAppNew return new instance of application
func GUIAppNew(port int32) (app GUIApp) {
	app.port = port
	app.mainWindow = initWindow("SimpleSecureTransferTool")
	app.mainLayout = getGridLayout()
	if isPasswordSet() {
		app.mainLayout.Add(app.getLoginLayout())
	} else {
		app.mainLayout.Add(app.getRegisterLayout())
	}
	app.mainWindow.Add(app.mainLayout)
	app.mainWindow.SetPosition(gtk.WIN_POS_CENTER)
	return
}

func (app *GUIApp) getLoginLayout() *gtk.Grid {
	callback := func(password string, layout *gtk.Grid, errorLabel *gtk.Label) {
		encryptor := EncryptedMessageHandler(32, CBC)
		encryptor.LoadKeys("config", password)
		layout.Destroy()
		app.passwordCallback(encryptor)
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
			app.passwordCallback(encryptor)
		}
	}
	newKeysButton := getButton("Generate new keys", newKeysCallback)
	passwordLayout.Attach(newKeysButton, 0, 4, 2, 1)
	return passwordLayout
}

func (app *GUIApp) getRegisterLayout() *gtk.Grid {
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
				app.passwordCallback(encryptor)
			}
		}
	}
	return getPasswordLayout("Enter new password", callback)
}

func (app *GUIApp) getConnectLayout() *gtk.Grid {
	layout := getGridLayout()
	titleLabel, _ := gtk.LabelNew("Targets IP address: ")
	addressCallback := func(textBox *gtk.Entry) {
		text, _ := textBox.GetText()
		app.addressChosenCallback(text)
	}
	addressBox := getTextBox(addressCallback)
	enterCallback := func(button *gtk.Button) {
		text, _ := addressBox.GetText()
		app.addressChosenCallback(text)
	}
	enterButton := getButton("Connect", enterCallback)
	layout.Attach(titleLabel, 0, 0, 1, 1)
	layout.Attach(addressBox, 1, 0, 1, 1)
	layout.Attach(enterButton, 0, 1, 2, 1)
	app.addressBox = addressBox
	return layout
}

func (app *GUIApp) getCipherChoiceLayout() *gtk.Grid {
	layout := getGridLayout()
	titleLabel, _ := gtk.LabelNew("Choose algorithm: ")
	choices := [4]string{"ECB", "CBC", "CFB", "OFB"}
	choicesBox, _ := gtk.ComboBoxTextNew()
	for i := 0; i < len(choices); i++ {
		choicesBox.AppendText(choices[i])
	}
	choicesBox.SetActive(1)
	selectButton := getButton("Select", func(button *gtk.Button) {
		app.cipherChosenCallback(choicesBox.GetActive())
	})
	layout.Attach(titleLabel, 0, 0, 2, 1)
	layout.Attach(choicesBox, 0, 1, 1, 1)
	layout.Attach(selectButton, 1, 1, 1, 1)
	app.cipherChoiceBox = choicesBox
	return layout
}

func (app *GUIApp) showSendFilePopup() {
	window, _ := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	window.SetTitle("Send File")
	window.Connect("destroy", func() {
		window.Destroy()
	})
	window.SetDefaultSize(1920/4, 1080/4)
	window.SetPosition(gtk.WIN_POS_CENTER)
	layout := getGridLayout()
	encryptProgressLayout, encryptProgressBar, encryptTimeLabel := getProgressBarLayout("Encryption progress: ")
	uploadProgressLayout, uploadProgressBar, uploadTimeLabel := getProgressBarLayout("Upload progress: ")
	filenameLabel, _ := gtk.LabelNew("...")
	sendFileButton := getButton("Send", func(button *gtk.Button) {
		filename, _ := filenameLabel.GetText()
		app.sendFileCallback(filename)
	})
	sendFileButton.SetSensitive(false)
	chooseFileButtonPressedCallback := func(button *gtk.Button) {
		filename := gtk.OpenFileChooserNative("Choose file to send", window)
		if filename != nil {
			filenameLabel.SetText(*filename)
			sendFileButton.SetSensitive(true)
		} else {
			filenameLabel.SetText("...")
			sendFileButton.SetSensitive(false)
		}
	}
	chooseFileButton := getButton("Choose File", chooseFileButtonPressedCallback)
	layout.Attach(filenameLabel, 0, 0, 1, 1)
	layout.Attach(chooseFileButton, 1, 0, 1, 1)
	layout.Attach(sendFileButton, 2, 0, 1, 1)
	layout.Attach(encryptProgressLayout, 0, 1, 3, 1)
	layout.Attach(uploadProgressLayout, 0, 2, 3, 1)
	app.encryptProgressBar = encryptProgressBar
	app.encryptTimeLabel = encryptTimeLabel
	app.uploadProgressBar = uploadProgressBar
	app.uploadTimeLabel = uploadTimeLabel
	window.Add(layout)
	window.ShowAll()
}

func (app *GUIApp) getMessagesLayout() *gtk.Grid {
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
		app.messageWrittenCallback(text)
	}
	textInput := getTextBox(textBoxCallback)
	promptLabel, _ := gtk.LabelNew("Write message: ")
	enterButtonCallback := func(button *gtk.Button) {
		text, _ := textInput.GetText()
		textBuffer.Insert(iter, "You: "+text+"\n")
		textInput.SetText("")
		app.messageWrittenCallback(text)
	}
	enterButton := getButton("Send", enterButtonCallback)
	scrolledWindow.Add(textView)
	layout.Attach(titleLabel, 0, 0, 3, 1)
	layout.Attach(scrolledWindow, 0, 1, 3, 1)
	layout.Attach(promptLabel, 0, 2, 1, 1)
	layout.Attach(textInput, 1, 2, 1, 1)
	layout.Attach(enterButton, 2, 2, 1, 1)
	app.messageTextBuffer = textBuffer
	app.messageTextIter = iter
	return layout
}

func (app *GUIApp) getConfigLayout() *gtk.Grid {
	layout := getGridLayout()
	addressLayout := app.getConnectLayout()
	cipherLayout := app.getCipherChoiceLayout()
	connectedLabel, _ := gtk.LabelNew("Connected: ")
	statusLabel, _ := gtk.LabelNew("No")
	separator, _ := gtk.SeparatorNew(gtk.ORIENTATION_HORIZONTAL)
	sendFileButtonPressedCallback := func(button *gtk.Button) {
		app.showSendFilePopup()
	}
	sendFileButton := getButton("Send file", sendFileButtonPressedCallback)
	layout.Attach(connectedLabel, 0, 0, 1, 1)
	layout.Attach(statusLabel, 1, 0, 1, 1)
	layout.Attach(separator, 0, 1, 2, 1)
	layout.Attach(addressLayout, 0, 2, 2, 1)
	layout.Attach(separator, 0, 3, 2, 1)
	layout.Attach(cipherLayout, 0, 4, 2, 1)
	layout.Attach(separator, 0, 5, 2, 1)
	layout.Attach(sendFileButton, 0, 6, 2, 2)
	app.connectionStatusLabel = statusLabel
	return layout
}

func (app *GUIApp) messageWrittenCallback(message string) {
	err := app.netClient.SendTextMessage(message)
	if err != nil {
		println(err.Error())
	}
	println("sending message: ", message)
}

func (app *GUIApp) cipherChosenCallback(cipher int) {
	app.netClient.SetCipher(cipherblockmode(cipher))
	err := app.netClient.SendConnectionProperties()
	if err != nil {
		println(err.Error())
	}
	println("Sending new cipher: ", cipher)
}

func (app *GUIApp) passwordCallback(encryptor EncMess) {
	leftLayout := app.getMessagesLayout()
	app.encryptor = encryptor
	app.netClient = NetClientInit(app.port, app.encryptor)
	go app.netClient.NetClientListen(app)
	pane, _ := gtk.PanedNew(gtk.ORIENTATION_HORIZONTAL)
	pane.Pack1(leftLayout, true, true)
	rightLayout := app.getConfigLayout()
	pane.Pack2(rightLayout, true, true)
	app.mainLayout.Add(pane)
	app.mainWindow.ShowAll()
}

func (app *GUIApp) addressChosenCallback(address string) {
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

func (app *GUIApp) sendFileCallback(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		app.showErrorPopup(err)
	} else {
		go app.netClient.SendFile(file, app)
	}
}

func (app *GUIApp) showErrorPopup(err error) {
	popup := gtk.MessageDialogNew(app.mainWindow, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, err.Error())
	popup.Connect("response", func() {
		popup.Destroy()
	})
	popup.Run()
}

//UpdateUploadProgress updates progress bar
func (app *GUIApp) UpdateUploadProgress(value float64, duration string) {
	glib.IdleAdd(func() {
		app.uploadProgressBar.SetFraction(value)
		app.uploadTimeLabel.SetText(duration)
	})
}

//UpdateCipherMode updates cipher mode choice box
func (app *GUIApp) UpdateCipherMode() {
	app.cipherChoiceBox.SetActive(int(app.netClient.GetCipher()))
}

//ShowMessage shows user message in the messaging box
func (app *GUIApp) ShowMessage(message string) {
	app.messageTextBuffer.Insert(app.messageTextIter, "Friend: "+message)
}

//ChangeAddress sets showed address to value
func (app *GUIApp) ChangeAddress(address string) {
	app.addressBox.SetText(address)
}

//SetConnected sets label to Yes if given true
func (app *GUIApp) SetConnected(connected bool) {
	if connected {
		app.connectionStatusLabel.SetText("Yes")
		go app.netClient.StartPinging(app)
	} else {
		app.connectionStatusLabel.SetText("No")
		app.ChangeAddress("")
	}
}

//RunGUI starts gui of the application
func (app *GUIApp) RunGUI() {
	app.mainWindow.ShowAll()
	gtk.Main()
}

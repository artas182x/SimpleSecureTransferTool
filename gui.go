package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

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
	messagesTextView  *gtk.TextView

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
	downloadProgressBar *gtk.ProgressBar
	downloadTimeLabel   *gtk.Label
	decryptProgressBar  *gtk.ProgressBar
	decryptTimeLabel    *gtk.Label

	//Inputs
	textInput          *gtk.Entry
	sendTextButton     *gtk.Button
	cipherSelectButton *gtk.Button
	sendFileButton     *gtk.Button

	//NetClient
	port      int32
	encryptor EncMess
	netClient NetClient
}

//GUIAppNew return new instance of application
func GUIAppNew(port int32) (app GUIApp) {
	app.port = port
	app.mainWindow = initWindow(fmt.Sprintf("SimpleSecureTransferTool - listening on port %d", port))
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
		encryptor.LoadKeys("config", password, app)
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
		err := encryptor.CreateKeys("config", string(password.(string)), app)
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
			err := encryptor.CreateKeys("config", password, app)
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
	titleLabel, _ := gtk.LabelNew("Target IP address: ")
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
	titleLabel, _ := gtk.LabelNew("Choose cipher mode: ")
	choices := [4]string{"ECB", "CBC", "CFB", "OFB"}
	choicesBox, _ := gtk.ComboBoxTextNew()
	for i := 0; i < len(choices); i++ {
		choicesBox.AppendText(choices[i])
	}
	choicesBox.SetActive(1)
	choicesBox.SetSensitive(false)
	selectButton := getButton("Select", func(button *gtk.Button) {
		app.cipherChosenCallback(choicesBox.GetActive())
	})
	selectButton.SetSensitive(false)
	layout.Attach(titleLabel, 0, 0, 2, 1)
	layout.Attach(choicesBox, 0, 1, 1, 1)
	layout.Attach(selectButton, 1, 1, 1, 1)
	app.cipherChoiceBox = choicesBox
	app.cipherSelectButton = selectButton
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
		str := fmt.Sprintf("%s You: %s\n", time.Now().Format("15:04"), text)
		textBuffer.Insert(iter, str)
		textBox.SetText("")
		app.messageWrittenCallback(text)
	}
	textInput := getTextBox(textBoxCallback)
	textInput.SetSensitive(false)
	promptLabel, _ := gtk.LabelNew("Write message: ")
	enterButtonCallback := func(button *gtk.Button) {
		text, _ := textInput.GetText()
		str := fmt.Sprintf("%s You: %s\n", time.Now().Format("15:04"), text)
		textBuffer.Insert(iter, str)
		textInput.SetText("")
		app.messageWrittenCallback(text)
	}
	enterButton := getButton("Send", enterButtonCallback)
	enterButton.SetSensitive(false)
	scrolledWindow.Add(textView)
	layout.Attach(titleLabel, 0, 0, 3, 1)
	layout.Attach(scrolledWindow, 0, 1, 3, 1)
	layout.Attach(promptLabel, 0, 2, 1, 1)
	layout.Attach(textInput, 1, 2, 1, 1)
	layout.Attach(enterButton, 2, 2, 1, 1)
	app.textInput = textInput
	app.sendTextButton = enterButton
	app.messageTextBuffer = textBuffer
	app.messageTextIter = iter
	app.messagesTextView = textView
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
	sendFileButton.SetSensitive(false)
	layout.Attach(connectedLabel, 0, 0, 1, 1)
	layout.Attach(statusLabel, 1, 0, 1, 1)
	layout.Attach(separator, 0, 1, 2, 1)
	layout.Attach(addressLayout, 0, 2, 2, 1)
	layout.Attach(separator, 0, 3, 2, 1)
	layout.Attach(cipherLayout, 0, 4, 2, 1)
	layout.Attach(separator, 0, 5, 2, 1)
	layout.Attach(sendFileButton, 0, 6, 2, 2)
	app.sendFileButton = sendFileButton
	app.connectionStatusLabel = statusLabel
	return layout
}

func (app *GUIApp) messageWrittenCallback(message string) {
	err := app.netClient.SendTextMessage(message, app)
	if err != nil {
		println(err.Error())
	}
	println("sending message: ", message)
	for {
		if gtk.EventsPending() {
			gtk.MainIterationDo(false)
		} else {
			break
		}
	}
	autoIter := app.messageTextBuffer.GetIterAtLine(app.messageTextBuffer.GetLineCount())
	app.messagesTextView.ScrollToIter(autoIter, 0.0, true, 0.5, 0.5)
}

func (app *GUIApp) cipherChosenCallback(cipher int) {
	app.netClient.setCipher(cipherblockmode(cipher))
	err := app.netClient.SendCipherMode()
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
	hash := sha256.Sum256(app.netClient.messageHandler.myPublicKey)
	hashLabel, _ := gtk.LabelNew("My public key SHA256 digest: " + hex.EncodeToString(hash[:]) + "\n")
	app.mainLayout.Attach(hashLabel, 0, 0, 1, 1)
	app.mainLayout.Attach(pane, 0, 1, 1, 1)
	app.mainWindow.ShowAll()
}

func (app *GUIApp) addressChosenCallback(address string) {
	if len(strings.Split(address, ":")) == 1 {
		address = fmt.Sprintf("%s:%d", address, 27002)
	}
	err := app.netClient.SendHello(address)
	if err != nil {
		println("not connected")
		app.messageTextBuffer.Insert(app.messageTextIter, fmt.Sprintf("%v\n", err))
		app.SetConnected(false)
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

//ShowDownloadFilePopup shows dialog containing downloading and decrypting file progress bar
func (app *GUIApp) ShowDownloadFilePopup(filename string) {
	window, _ := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	window.SetTitle("Downloading File")
	window.Connect("destroy", func() {
		window.Destroy()
	})
	window.SetDefaultSize(1920/4, 1080/4)
	window.SetPosition(gtk.WIN_POS_CENTER)
	layout := getGridLayout()
	decryptProgressLayout, decryptProgressBar, decryptTimeLabel := getProgressBarLayout("Decryption progress: ")
	downloadProgressLayout, downloadProgressBar, downloadTimeLabel := getProgressBarLayout("Download progress: ")
	filenameLabel, _ := gtk.LabelNew(filename)
	layout.Attach(filenameLabel, 0, 0, 3, 1)
	layout.Attach(downloadProgressLayout, 0, 1, 3, 1)
	layout.Attach(decryptProgressLayout, 0, 2, 3, 1)
	app.decryptProgressBar = decryptProgressBar
	app.decryptTimeLabel = decryptTimeLabel
	app.downloadProgressBar = downloadProgressBar
	app.downloadTimeLabel = downloadTimeLabel
	window.Add(layout)
	window.ShowAll()
}

//UpdateDecryptionProgress updates decryption status
func (app *GUIApp) UpdateDecryptionProgress(value float64, duration string) {
	app.decryptProgressBar.SetFraction(value)
	app.decryptTimeLabel.SetText(duration)
}

//UpdateDownloadProgress updates download status
func (app *GUIApp) UpdateDownloadProgress(value float64, duration string) {
	app.downloadProgressBar.SetFraction(value)
	app.downloadTimeLabel.SetText(duration)
}

//UpdateEncryptionProgress updates encryption status
func (app *GUIApp) UpdateEncryptionProgress(value float64, duration string) {
	app.encryptProgressBar.SetFraction(value)
	app.encryptTimeLabel.SetText(duration)
}

//UpdateUploadProgress updates upload status
func (app *GUIApp) UpdateUploadProgress(value float64, duration string) {
	app.uploadProgressBar.SetFraction(value)
	app.uploadTimeLabel.SetText(duration)
}

//UpdateCipherMode updates cipher mode choice box
func (app *GUIApp) UpdateCipherMode() {
	app.cipherChoiceBox.SetActive(int(app.netClient.getCipher()))
}

//ShowMessage shows user message in the messaging box
func (app *GUIApp) ShowMessage(message string) {
	app.PushMessageToBuffer("Friend: " + message)
}

//PushMessageToBuffer shows message in the messaging box
func (app *GUIApp) PushMessageToBuffer(message string) {
	str := fmt.Sprintf("%s %s", time.Now().Format("15:04"), message)
	app.messageTextBuffer.Insert(app.messageTextIter, str)
	for {
		if gtk.EventsPending() {
			gtk.MainIterationDo(false)
		} else {
			break
		}
	}
	autoIter := app.messageTextBuffer.GetIterAtLine(app.messageTextBuffer.GetLineCount())
	app.messagesTextView.ScrollToIter(autoIter, 0.0, true, 0.5, 0.5)
}

//ChangeAddress sets showed address to value
func (app *GUIApp) ChangeAddress(address string) {
	if app.addressBox != nil {
		glib.IdleAdd(func() {
			app.addressBox.SetText(address)
		})
	}
}

//SetConnected sets label to Yes if given true
func (app *GUIApp) SetConnected(connected bool) {
	app.netClient.SetClientState(connected)

	if connected {
		go app.netClient.StartPinging(app)
	}

	if app.connectionStatusLabel != nil {
		glib.IdleAdd(func() {
			if connected {
				app.connectionStatusLabel.SetText("Yes")
				app.PushMessageToBuffer("Connected\n")
			} else {
				app.connectionStatusLabel.SetText("No")
				app.PushMessageToBuffer("Disconnected\n")
			}

			app.textInput.SetSensitive(connected)
			app.sendTextButton.SetSensitive(connected)
			app.cipherChoiceBox.SetSensitive(connected)
			app.cipherSelectButton.SetSensitive(connected)
			app.sendFileButton.SetSensitive(connected)
		})
	}
}

//RunGUI starts gui of the application
func (app *GUIApp) RunGUI() {
	app.mainWindow.ShowAll()
	gtk.Main()
}

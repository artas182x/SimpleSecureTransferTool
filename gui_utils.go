package main

import (
	"github.com/gotk3/gotk3/gtk"
	"log"
	"os"
)

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

func initWindow(title string) (window *gtk.Window) {
	gtk.Init(nil)
	window, _ = gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	window.SetTitle(title)
	window.Connect("destroy", func() {
		gtk.MainQuit()
	})
	window.SetDefaultSize(1920/2, 1080/2)
	return window
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

func getProgressBar() *gtk.ProgressBar {
	progressBar, _ := gtk.ProgressBarNew()
	styleContext, _ := progressBar.GetStyleContext()
	mRefProvider, _ := gtk.CssProviderNew()
	if err := mRefProvider.LoadFromPath("styles.css"); err != nil {
		log.Println(err)
	}
	styleContext.AddProvider(mRefProvider, gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
	return progressBar
}

func getProgressBarLayout(title string) (layout *gtk.Grid, progressBar *gtk.ProgressBar, timeLabel *gtk.Label) {
	layout = getGridLayout()
	progressBar = getProgressBar()
	timeLabel, _ = gtk.LabelNew("0s")
	titleLabel, _ := gtk.LabelNew(title)
	layout.Attach(titleLabel, 0, 0, 1, 1)
	layout.Attach(progressBar, 1, 0, 1, 1)
	layout.Attach(timeLabel, 2, 0, 1, 1)
	return layout, progressBar, timeLabel
}

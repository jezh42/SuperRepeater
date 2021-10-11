package burp;

import java.awt.*;
import java.awt.event.MouseAdapter;
import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.GridLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TODO List
 * Send button number input
 * Inspector (focus on JWT)
 * Title formatting
 * cancel button support
 * Tabs
 * Logs
 * Ensure that all repeated sends are captured and displayed
 * Layout usability
 * Back and forward button (if suitable)
 * Toggle layout
 * Send button order toggle
 * listener on response for empty toggle visibility
 * Send status counter (with loading animation) using
 * ...
 * ...
 * Make everything thread safe
 */

public class BurpExtender implements IContextMenuFactory, IBurpExtender, ITab, IMessageEditorController {

    // Debug
    private boolean showBorders = false;

    // Burp Extender Inits
    private final String extensionName = "Super Repeater";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // Outputs
    private PrintWriter stdout;
    private PrintWriter stderr;

    // Pane
    private JPanel contentPane;
    private JPanel menuPane;
    private JPanel threePanelContainer;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private JPanel inspectorViewer;
    private JLabel httpServiceLabel;


    // Buttons
    JButton sendSplitButton;
    JButton cancelButton;
    JLabel sendStatusLabel;

    // HTTP
    private IHttpRequestResponse currentlyDisplayedItem;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        // Initializers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(this.extensionName);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerContextMenuFactory(this);
        // this.callbacks.registerExtensionStateListener(this);

        // Initialize the currently displayed item
        resetCurrentlyDisplayedItem();

        // Set up the Swing stuff
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                contentPane = new JPanel(new GridBagLayout());

                stdout.println("Loading Menu Pane...");
                // Menu Buttons
                makeMenuPane();
                stdout.println("Menu Pane Loaded");

                // Request
                stdout.println("Loading Request Pane...");
                String requestString = "Request";
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, true);
                JPanel requestPane = makeMessageEditorPane(requestString, requestViewer);
                if (showBorders) { requestPane.setBorder(BorderFactory.createLineBorder(Color.BLACK)); }
                stdout.println("Request Pane Loaded");

                // Response
                stdout.println("Loading Response Pane...");
                String responseString = "Response";
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                JPanel responsePane = makeMessageEditorPane(responseString, responseViewer);
                if (showBorders) {  responsePane.setBorder(BorderFactory.createLineBorder(Color.BLACK)); }
                // Add ? listener for responseviewer to toggle visibility for empty
                //responseViewer.getComponent().add
                stdout.println("Response Pane Loaded");

                // Inspector
                stdout.println("Loading Inspector Pane...");
                inspectorViewer = new JPanel();
                JLabel inspectorLabel = new JLabel("Inspector");
                inspectorViewer.add(inspectorLabel);
                stdout.println("Inspector Pane Loaded");

                stdout.println("Loading ThreePanelContainer Pane...");
                threePanelContainer = new JPanel(new GridLayout(1,3));
                threePanelContainer.add(requestPane);
                threePanelContainer.add(responsePane);
                threePanelContainer.add(inspectorViewer);
                stdout.println("ThreePanelContainer Pane Loaded");

                // Add everything to the Content GridBagLayout
                stdout.println("Adding Menu Pane to ContentPane...");
                GridBagConstraints menuPaneConstraints = new GridBagConstraints();
                menuPaneConstraints.fill = GridBagConstraints.HORIZONTAL;
                menuPaneConstraints.anchor = GridBagConstraints.PAGE_START;
                menuPaneConstraints.weightx = 1.0;
                menuPaneConstraints.weighty = 0;
                menuPaneConstraints.gridx = 0;
                menuPaneConstraints.gridy = 0;
                contentPane.add(menuPane, menuPaneConstraints);
                stdout.println("Menu Pane added to ContentPane");

                stdout.println("Adding ThreePanelContainer to ContentPane...");
                GridBagConstraints threePanelConstraints = new GridBagConstraints();
                threePanelConstraints.fill = GridBagConstraints.BOTH;
                threePanelConstraints.weightx = 1.0;
                threePanelConstraints.weighty = 1.0;
                threePanelConstraints.gridx = 0;
                threePanelConstraints.gridy = 1;
                contentPane.add(threePanelContainer, threePanelConstraints);
                stdout.println("ThreePanelContainer added to ContentPane");

                // Add new tab to Burp
                stdout.println("Adding SuiteTab to BurpSuite...");
                callbacks.addSuiteTab(BurpExtender.this);

                stdout.println("Extension fully loaded");
                stdout.println("**************************************************\n");
            }
        });
    }

    /**
     * Send button that displays a dropdown of alternative sends if clicked on the right
     * @return JButton
     */
    private JButton makeSendSplitButton() {
        // Make the dropdown menu
        JPopupMenu sendPopupMenu = new JPopupMenu();

        // Send 10x
        JMenuItem sendMenuSendTenTimes = new JMenuItem("Send x10");
        sendMenuSendTenTimes.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                sendRequest(10);
            }
        });
        sendPopupMenu.add(sendMenuSendTenTimes);

        // Send 20x
        JMenuItem sendMenuSendTwentyTimes = new JMenuItem("Send x20");
        sendMenuSendTwentyTimes.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                sendRequest(20);
            }
        });
        sendPopupMenu.add(sendMenuSendTwentyTimes);


        // Create the button and the conditional mouse event listener
        JButton sendSplitButton = new JButton("Send | *");
        sendSplitButton.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                int mouseX = e.getX();

                if (mouseX < 50 ) {
                    // Perform Send if clicks the Send word
                    sendRequest(1);

                } else if (mouseX > 50) {
                    // Display the dropdown if clicks the *
                    sendPopupMenu.show(
                            e.getComponent(),
                            0,
                            (int) sendSplitButton.getHeight()
                    );
                }
            }
        });

        return sendSplitButton;
    }

    /**
     *
     * @param requestCount
     */
    private void sendRequest(int requestCount) {

        SuperRepeaterSender sender = new SuperRepeaterSender(
                callbacks,
                this.getHttpService(),
                this.getRequest(),
                requestCount,
                this.sendStatusLabel
        );

        List<IHttpRequestResponse> responses = sender.send();

        this.currentlyDisplayedItem = responses.get(requestCount-1);

        this.responseViewer.setMessage(this.currentlyDisplayedItem.getResponse(), false);
    }

    /**
     *
     * @return
     */
    private JButton makeCancelButton() {
        cancelButton = new JButton("Cancel");

        // Start it disabled
        cancelButton.setEnabled(false);

        cancelButton.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                cancelButton.setEnabled(false);
            }
        });

        return cancelButton;
    }

    /**
     * Make the menu pane with buttons
     * TODO: Make it a GridBagLayout to make it look nicer
     */
    private void makeMenuPane() {

        // Left Side of the Menu
        stdout.println("Loading menuPaneLeft...");
        JPanel menuPaneLeft = new JPanel(new FlowLayout(FlowLayout.LEFT));
        if (showBorders) { menuPaneLeft.setBorder(BorderFactory.createLineBorder(Color.BLUE)); }
        this.sendSplitButton = makeSendSplitButton();
        this.cancelButton = makeCancelButton();
        this.sendStatusLabel = new JLabel("");
        this.sendStatusLabel.setVisible(false);
        menuPaneLeft.add(sendSplitButton);
        menuPaneLeft.add(cancelButton);
        menuPaneLeft.add(sendStatusLabel);
        stdout.println("menuPaneLeft Loaded");

        // Right Side of the Menu
        stdout.println("Loading menuPaneRight...");
        JPanel menuPaneRight = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        if (showBorders) { menuPaneRight.setBorder(BorderFactory.createLineBorder(Color.RED)); }
        // Label
        httpServiceLabel = new JLabel("Target: Not Specified");
        updateHttpServiceLabel(this.getHttpService());
        menuPaneRight.add(httpServiceLabel);
        stdout.println("menuPaneRight Loaded");

        // Add them to the menu
        stdout.println("Combining menuPane...");
        this.menuPane = new JPanel(new GridLayout(1,2));
        this.menuPane.add(menuPaneLeft);
        this.menuPane.add(menuPaneRight);
        stdout.println("menuPane combined");

        if (showBorders) { this.menuPane.setBorder(BorderFactory.createLineBorder(Color.GREEN)); }

        // Set the size of the menu to restrict the height
        this.menuPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 3));
    }

    /**
     *
     */
    private void updateHttpServiceLabel(IHttpService currentHttpService) {
        stdout.println("Updating HttpServiceLabel...");

        if (currentHttpService != null) {
            this.httpServiceLabel.setText("Target: " +
                    currentHttpService.getProtocol() + "://" +
                    currentHttpService.getHost() + ":" +
                    currentHttpService.getPort()
            );
        }

        stdout.println("HttpServiceLabel updated");
    }

    /**
     *
     * @param labelString
     * @param messageEditor
     * @return
     */
    private JPanel makeMessageEditorPane(String labelString, IMessageEditor messageEditor){
        JPanel messageEditorPane = new JPanel(new GridBagLayout());

        JLabel label = new JLabel(labelString);
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        labelConstraints.anchor = GridBagConstraints.PAGE_START;
        labelConstraints.ipady = 20;
        labelConstraints.weightx = 1.0;
        labelConstraints.weighty = 0;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        messageEditorPane.add(label, labelConstraints);

        JPanel messageEditorContainer = new JPanel(new GridBagLayout());
        GridBagConstraints messageEditorContainerConstraints = new GridBagConstraints();
        messageEditorContainerConstraints.fill = GridBagConstraints.BOTH;
        messageEditorContainerConstraints.weightx = 1.0;
        messageEditorContainerConstraints.weighty = 1.0;
        messageEditorContainer.add(messageEditor.getComponent(), messageEditorContainerConstraints);

        GridBagConstraints messageEditorConstraints = new GridBagConstraints();
        messageEditorConstraints.fill = GridBagConstraints.BOTH;
        messageEditorConstraints.weightx = 1.0;
        messageEditorConstraints.weighty = 1.0;
        messageEditorConstraints.gridx = 0;
        messageEditorConstraints.gridy = 1;
        messageEditorPane.add(messageEditorContainer, messageEditorConstraints);

        return messageEditorPane;
    }

    @Override
    public String getTabCaption() {
        return extensionName;
    }

    @Override
    public Component getUiComponent() {
        return contentPane;
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    /**
     * Reset CurrentlyDisplayedItem to empty values
     */
    private void resetCurrentlyDisplayedItem() {

        stdout.println("Resetting currentlyDisplayedItem...");

        this.currentlyDisplayedItem = new IHttpRequestResponse() {
            @Override
            public byte[] getRequest() {
                return new byte[0];
            }

            @Override
            public void setRequest(byte[] message) {

            }

            @Override
            public byte[] getResponse() {
                return new byte[0];
            }

            @Override
            public void setResponse(byte[] message) {

            }

            @Override
            public String getComment() {
                return null;
            }

            @Override
            public void setComment(String comment) {

            }

            @Override
            public String getHighlight() {
                return null;
            }

            @Override
            public void setHighlight(String color) {

            }

            @Override
            public IHttpService getHttpService() {
                return null;
            }

            @Override
            public void setHttpService(IHttpService httpService) {

            }
        };

        byte[] fakeReq = {};
        this.currentlyDisplayedItem.setRequest(new byte[0]);

        stdout.println("currentlyDisplayedItem reset!");
        stdout.println("currentlyDisplayedItem.getRequest(): " +
                helpers.bytesToString(this.currentlyDisplayedItem.getRequest())
        );
        stdout.println("currentlyDisplayedItem.getResponse(): " +
                helpers.bytesToString(this.currentlyDisplayedItem.getResponse())
        );
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> contextMenuList = new ArrayList<>();

        JMenuItem sendToSuperRepeater = new JMenuItem("Send to Super Repeater");
        sendToSuperRepeater.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                // Send the first selected item (for now)
                IHttpRequestResponse clickedItem = invocation.getSelectedMessages()[0];
                byte[] request = clickedItem.getRequest();
                byte[] response = clickedItem.getResponse();
                IHttpService httpService = clickedItem.getHttpService();

                if (request != null && request.length != 0){
                    stdout.println("Request Length:" + request.length);
                    //stdout.println("Request:" + helpers.bytesToString(request));
                    stdout.println("Request: " + Arrays.toString(request));
                    requestViewer.setMessage(request, true);
                }

                /* Decided to change it so won't load the response
                if (response != null && response.length != 0){
                    stdout.println("Response Length:" + response.length);
                    stdout.println("Response:" + helpers.bytesToString(response));
                    responseViewer.setMessage(response, false);
                }
                */

                if (httpService != null) {
                    stdout.println("Setting HTTP Service");
                    updateHttpServiceLabel(httpService);
                }

                currentlyDisplayedItem = clickedItem;
            }
        });

        // If what being selected is a request that can be sent to Super Repeater
        //   then show the context menu item
        byte contextCode = invocation.getInvocationContext();
        stdout.println("Context: " + contextCode);
        if (contextCode == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                contextCode == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
                contextCode == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE ||
                contextCode == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST){
            contextMenuList.add(sendToSuperRepeater);
        }

        return contextMenuList;
    }
}

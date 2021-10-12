package burp;

import java.awt.*;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;
import javax.swing.*;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TODO List
 * Tabs
 * main tab highlight on change
 *
 * Logs
 *   default column size
 *   params
 *   cookies
 *   change order
 *
 * Inspector (focus on JWT)
 * listener for each of the message viewers
 *
 * Title formatting
 * cancel button support
 *
 *
 *
 *
 * Ensure that all repeated sends are captured and displayed
 * Layout usability
 * Back and forward button (if suitable)
 * Toggle layout
 * Send button order toggle (maybe not)
 * application wide capture of logs
 * listener on response for empty toggle visibility
 * Send status counter (with loading animation) using
 * ...
 * ...
 * Make everything thread safe
 */

public class BurpExtender extends AbstractTableModel implements IContextMenuFactory, IBurpExtender, ITab, IMessageEditorController {

    // Debug
    private boolean showBorders = true;

    // Burp Extender Inits
    private final String extensionName = "Super Repeater";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // Outputs
    private PrintWriter stdout;
    private PrintWriter stderr;

    // Pane
    private JTabbedPane tabs;
    private JPanel contentPane;
    private JPanel menuPane;
    private JPanel logScrollPane;
    private final List<LogEntry> logs = new ArrayList<LogEntry>();
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
                tabs = new JTabbedPane();

                contentPane = new JPanel(new GridBagLayout());

                // Menu Pane
                makeMenuPane();

                // Logs
                makeLogPane();

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

                stdout.println("Adding Log Scroll Pane to ContentPane...");
                GridBagConstraints logScrollPaneConstraints = new GridBagConstraints();
                logScrollPaneConstraints.fill = GridBagConstraints.BOTH;
                logScrollPaneConstraints.weightx = 1.0;
                logScrollPaneConstraints.weighty = 0.2;
                logScrollPaneConstraints.gridx = 0;
                logScrollPaneConstraints.gridy = 1;
                contentPane.add(logScrollPane, logScrollPaneConstraints);
                stdout.println("Log Scroll Pane added to ContentPane");

                stdout.println("Adding ThreePanelContainer to ContentPane...");
                GridBagConstraints threePanelConstraints = new GridBagConstraints();
                threePanelConstraints.fill = GridBagConstraints.BOTH;
                threePanelConstraints.weightx = 1.0;
                threePanelConstraints.weighty = 1.0;
                threePanelConstraints.gridx = 0;
                threePanelConstraints.gridy = 2;
                contentPane.add(threePanelContainer, threePanelConstraints);
                stdout.println("ThreePanelContainer added to ContentPane");

                tabs.addTab("1", contentPane);

                callbacks.customizeUiComponent(tabs);

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

        // Send 20x
        JMenuItem sendMenuSendCustom = new JMenuItem("Send custom amount");
        sendMenuSendCustom.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {

                // Make popup with input
                String input = JOptionPane.showInputDialog(
                        null,
                        "Enter a number for how many requests you want to make (1-10,000)"
                );

                int customAmount = Integer.parseInt(input);

                if (customAmount > 1 && customAmount < 10000) {
                    stdout.println("Sending custom amount" + customAmount);
                    sendRequest(customAmount);
                } else {
                    stdout.println("Error sending");
                }

            }
        });
        sendPopupMenu.add(sendMenuSendCustom);


        // Create the button and the conditional mouse event listener
        JButton sendSplitButton = new JButton("Send │ ▼");
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

        // Make the sender
        SuperRepeaterSender sender = new SuperRepeaterSender(
                callbacks,
                this.getHttpService(),
                this.getRequest(),
                requestCount,
                this.sendStatusLabel
        );

        // Send the requests
        List<IHttpRequestResponse> requestResponses = sender.send();

        // Process the responses into the logs
        for (IHttpRequestResponse requestResponse : requestResponses) {

            //synchronized (logs) {
                int row = logs.size();
                logs.add(new LogEntry(
                    callbacks.saveBuffersToTempFiles(requestResponse),
                    helpers.analyzeRequest(requestResponse).getMethod(),
                    helpers.analyzeRequest(requestResponse).getUrl(),
                    helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode(),
                    requestResponse.getResponse().length
                ));

                stdout.println("################################################");
                stdout.println("Length: " + requestResponse.getResponse().length);
                stdout.println("Headers: " + helpers.analyzeResponse(requestResponse.getResponse()).getHeaders());
                stdout.println("################################################");

                fireTableRowsInserted(row, row);
            //}
        }

        // Display the last response
        this.currentlyDisplayedItem = requestResponses.get(requestCount-1);
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
     */
    private void makeLogPane() {

        stdout.println("Loading Log viewer...");

        LogTable logTable = new LogTable(BurpExtender.this);

        // Set the Column Widths
        // TODO: fix
        logTable.getColumn("#").setWidth(1);
        logTable.getColumn("Method").setWidth(2);
        logTable.getColumn("URL").setWidth(5);
        logTable.getColumn("Status").setWidth(3);
        logTable.getColumn("Length").setWidth(3);

        logScrollPane = new JPanel(new GridLayout(1,1));

        JScrollPane logScrollView = new JScrollPane(logTable);
        logScrollPane.add(logScrollView);
        logScrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 3));

        if (showBorders) { logTable.setBorder(BorderFactory.createLineBorder(Color.CYAN)); }
        if (showBorders) { logScrollView.setBorder(BorderFactory.createLineBorder(Color.MAGENTA)); }
        if (showBorders) { logScrollPane.setBorder(BorderFactory.createLineBorder(Color.ORANGE)); }

        callbacks.customizeUiComponent(logTable);
        callbacks.customizeUiComponent(logScrollPane);

        stdout.println("Log Viewer Loaded");
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
        return tabs;
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

    /**
     *
     */
    private class LogTable extends JTable {

        public LogTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {

            LogEntry log = logs.get(row);
            requestViewer.setMessage(log.requestResponse.getRequest(), true);
            responseViewer.setMessage(log.requestResponse.getResponse(), false);
            currentlyDisplayedItem = log.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     *
     */
    private static class LogEntry {

        final int length;
        final String method;
        final IHttpRequestResponse requestResponse;
        final int status;
        final URL url;

        LogEntry(
                IHttpRequestResponsePersisted requestResponse,
                String method,
                URL url,
                int status,
                int length
        ) {
            this.requestResponse = requestResponse;
            this.method = method;
            this.url = url;
            this.status = status;
            this.length = length;
        }
    }

    /**
     *
     * @return
     */
    @Override
    public int getRowCount() {
        return logs.size();
    }

    /**
     *
     * @return
     */
    @Override
    public int getColumnCount() {
        return 5;
    }

    /**
     *
     * @param columnIndex
     * @return
     */
    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Length";
            default:
                return "";
        }
    }

    /**
     *
     * @param columnIndex
     * @return
     */
    @Override
    public Class<?> getColumnClass(int columnIndex){
        return String.class;
    }

    /**
     *
     * @param rowIndex
     * @param columnIndex
     * @return
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {

        LogEntry log = logs.get(rowIndex);

        switch (columnIndex) {
            case 0: // #
                return rowIndex;
            case 1: // Method
                return log.method;
            case 2: // URL
                return log.url.toString();
            case 3: // Status
                return Integer.toString(log.status);
            case 4: // Length
                return Integer.toString(log.length);
            default:
                return "";
        }
    }
}

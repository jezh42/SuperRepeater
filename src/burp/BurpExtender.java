package burp;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.net.URL;
import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.GridLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IContextMenuFactory, IBurpExtender, ITab, IMessageEditorController {

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

    // Buttons
    JButton sendSplitButton;
    JButton cancelButton;

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

        // Set up the Swing stuff
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                contentPane = new JPanel(new GridBagLayout());
                GridBagConstraints constraints = new GridBagConstraints();

                // Menu Buttons
                makeMenuPane();

                // Request
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, true);

                // Response
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);

                // Inspector
                inspectorViewer = new JPanel();
                JLabel inspectorLabel = new JLabel("Inspector");
                inspectorViewer.add(inspectorLabel);

                threePanelContainer = new JPanel(new GridLayout(1,3));
                threePanelContainer.add(requestViewer.getComponent());
                threePanelContainer.add(responseViewer.getComponent());
                threePanelContainer.add(inspectorViewer);

                // Add everything to the Content GridBagLayout
                constraints.fill = GridBagConstraints.HORIZONTAL;
                constraints.anchor = GridBagConstraints.PAGE_START;
                //constraints.ipadx = 0;
                constraints.ipady = 20;
                constraints.weightx = 1.0;
                constraints.weighty = 0;
                constraints.gridx = 0;
                constraints.gridy = 0;
                contentPane.add(menuPane, constraints);

                constraints.fill = GridBagConstraints.BOTH;
                //constraints.anchor =
                //constraints.ipadx = 0;
                //constraints.ipady = GRID;
                constraints.weightx = 1.0;
                constraints.weighty = 1.0;
                constraints.gridx = 0;
                constraints.gridy = 1;
                contentPane.add(threePanelContainer, constraints);

                // Add new tab to Burp
                callbacks.addSuiteTab(BurpExtender.this);
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
                cancelButton.setEnabled(false);
            }
        });
        sendPopupMenu.add(sendMenuSendTenTimes);

        // Send 20x
        JMenuItem sendMenuSendTwentyTimes = new JMenuItem("Send x20");
        sendMenuSendTwentyTimes.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                cancelButton.setEnabled(false);
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
                    cancelButton.setEnabled(true);
                    // Send the request

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
     */
    private void makeMenuPane() {

        // Left Side of the Menu
        JPanel menuPaneLeft = new JPanel(new FlowLayout(FlowLayout.LEFT));
        this.sendSplitButton = makeSendSplitButton();
        this.cancelButton = makeCancelButton();
        menuPaneLeft.add(sendSplitButton);
        menuPaneLeft.add(cancelButton);

        // Right Side of the Menu
        JPanel menuPaneRight = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton testButton = new JButton("Test button");
        menuPaneRight.add(testButton);

        // Add them to the menu
        this.menuPane = new JPanel(new GridLayout(1,2));
        this.menuPane.add(menuPaneLeft);
        this.menuPane.add(menuPaneRight);

        // Set the size of the menu to restrict the height
        this.menuPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 5));
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
                stdout.println("Request:" + helpers.bytesToString(request));
                stdout.println("Response:" + helpers.bytesToString(response));
                if (request.length != 0){
                    requestViewer.setMessage(request, true);
                }
                if (response.length != 0){
                    responseViewer.setMessage(response, false);
                }
                currentlyDisplayedItem = clickedItem;
            }
        });

        // If what being selected is a request that can be sent to Super Repeater
        //   then show the context menu item
        byte contextCode = invocation.getInvocationContext();
        //stdout.println("Context: " + contextCode);
        if (contextCode == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                contextCode == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
                contextCode == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE ||
                contextCode == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST){
            contextMenuList.add(sendToSuperRepeater);
        }

        return contextMenuList;
    }
}

package burp;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * TODO:
 * Consider making a new thread for each request <- current
 * Or one thread to loop through the requests
 */
public class SuperRepeaterSender implements Runnable {


    private Thread[] threadArray;

    private IBurpExtenderCallbacks callbacks;
    private IHttpService httpService;
    private byte[] request;
    private int count;
    private JLabel sendStatusLabel;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private List<IHttpRequestResponse> responses;

    /**
     *
     * @param callbacks
     * @param httpService
     * @param request
     * @param count
     */
    SuperRepeaterSender(
            IBurpExtenderCallbacks callbacks,
            IHttpService httpService,
            byte[] request,
            int count,
            JLabel sendStatusLabel
    ) {
        this.callbacks = callbacks;
        this.httpService = httpService;
        this.request = request;
        this.count = count;
        this.sendStatusLabel = sendStatusLabel;

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        stdout.println("Preparing to send "
                + count +
                ((count > 1) ? " requests " : " request ") +
                "to " +
                httpService.getHost()
        );
    }


    /**
     *
     */
    @Override
    public void run() {

        stdout.println("Thread running...");

        // Send the request
        if (httpService != null && request != null){
            try {

                stdout.println("thread making request...");

                IHttpRequestResponse reqres = callbacks.makeHttpRequest(httpService, request);

                stdout.println("thread got response of size [" + reqres.getResponse().length + "]");

                responses.add(reqres);

            } catch (Exception e) {
                stderr.println("Error: " + e.toString());
            }
        }

        stdout.println("Thread ending.");
    }

    /**
     * Sends all the requests
     * Currently will return the last response
     * @return
     */
    public List<IHttpRequestResponse> send() {

        threadArray = new Thread[count];
        responses = new ArrayList<IHttpRequestResponse>(count);


        // Create and start threads
        for (int i = 0; i < count; i++) {
            // Create the thread
            try{
                stdout.println("Create thread for request");
                threadArray[i] = new Thread(this);
            } catch (Exception e) {
                stderr.println("Thread [" + i + "] couldn't be created");
            }

            // Start the thread
            try{
                stdout.println("Trying to send request [" + i + "]");
                threadArray[i].start();
            } catch (Exception e) {
                stderr.println("Thread [" + i + "] couldn't be started");
            }
        }

        // Let the threads run concurrently,
        // and wait for them to finish in a second loop
        for (int i = 0; i < count; i++) {
            try {
                threadArray[i].join();
            } catch (InterruptedException e) {
                stderr.println(e);
            }
        }

        sendStatusLabel.setText("Sent " + count + ((count>1) ? " requests": " request"));
        sendStatusLabel.setVisible(true);

        stdout.println("All Requests sent");

        return responses;
    }

}

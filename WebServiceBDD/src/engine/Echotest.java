package engine;

import javax.servlet.http.HttpServlet;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * Servlet implementation class Echotest
 */
@Path("/Echotest")
public class Echotest extends HttpServlet {
	private static final long serialVersionUID = 1L;
       

    public Echotest() {
        super();
        // TODO Auto-generated constructor stub
    }
    
    @GET
	@Produces( MediaType.TEXT_PLAIN )
	public String sayPlainTextHello(){
    	return "error";
    }
}

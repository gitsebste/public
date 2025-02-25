using System;
using System.Data.SqlClient;

public class SQLInjectionExample
{
    public void ExecuteQuery(string userInput)
    {
        string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
        string query = "SELECT * FROM Users WHERE Name = '" + userInput + "'";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();
            SqlCommand command = new SqlCommand(query, connection);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine(reader["Name"]);
            }
        }
    }
}

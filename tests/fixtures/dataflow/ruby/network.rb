class Network
  def self.run_ping(target)
    system("ping -c 1 #{target}")
  end
end

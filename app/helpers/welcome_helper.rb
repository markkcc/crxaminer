module WelcomeHelper
  def severity_color_class(severity)
    case severity.to_s.downcase
    when 'critical'
      'bg-violet-600'
    when 'high'
      'bg-red-600'
    when 'medium'
      'bg-yellow-500'
    when 'low'
      'bg-blue-500'
    else
      'bg-gray-500'
    end
  end
end

def test_where
    # ruleid: AIK_ruby_check-sql
    Product.where("name = '#{params[:name]}'").first
    # ruleid: AIK_ruby_check-sql
    Product.where(["name = #{params[:name]}", params[:admin]])
    # ok: AIK_ruby_check-sql
    Product.where(:name => params[:name])
    # ok: AIK_ruby_check-sql
    Product.where({:name => params[:name]})

    # ruleid: AIK_ruby_check-sql
    Product.find_by(["name = #{params[:name]}", params[:admin]])
  end

  def test_find
    # ruleid: AIK_ruby_check-sql
    Product.find(:all, :conditions => "name = '#{params[:name]}'")
    # ruleid: AIK_ruby_check-sql
    Product.find(:all, :conditions => ["name = #{params[:name]}"])
    # ok: AIK_ruby_check-sql
    Product.find(:all, :conditions => {:name => params[:name]})
  end

  def test_specials
    # ruleid: AIK_ruby_check-sql
    Order.calculate(:sum, params[:column])
  end

  def aikido_true_vuln
    # see - https://rails-sqli.org/
    # ruleid: AIK_ruby_check-sql
    payroll_period = Payroll::Period.find_by(params[:period])

    attr = params[:attr]
    # ruleid: AIK_ruby_check-sql
    user = User.find_by(attr)
  end

  def aikido_safe_samples
    # ok: AIK_ruby_check-sql
    Product.find(:all, :order => params[:order])
    # ok: AIK_ruby_check-sql
    user = User.find_by(email: params[:user_email])
    # ok: AIK_ruby_check-sql
    transaction = AccountTransaction.find(params[:id])
    # ok: AIK_ruby_check-sql
    timeseries_for_asset = timeseries.select{ |tick| [tick[:asset_type], tick[:asset_id]] == [asset[:asset_type], asset[:asset_id].to_s] }
    
    # ok: AIK_ruby_check-sql
    company_type = CompanyType.find_by_title params[:type_filter]

    resources = params[:resources]
    # ok: AIK_ruby_check-sql
    resources = resources.group('companies.id')

    @tag_name = params[:tag]
    # ok: AIK_ruby_check-sql
    @posts = Blog::Tag.find_by_name!(@tag_name).posts.published.sorted_by_date.page params[:page]

    @reservist = params[:rev]
    # ok: AIK_ruby_check-sql
    CancellationMailer.delay.notification(@reservist)

    # ok: AIK_ruby_check-sql
    results = results.where('brewery_auth_core_users.email': params['email'].chomp) if params[:email]

    # ok: AIK_ruby_check-sql
    results = results.where("brewery_auth_core_users.email": params['email'].chomp) if params[:email]

    # ok: AIK_ruby_check-sql
    profile_channel = ProfileChannel.find_by "id" => params[:id], "actor.id" => @api_user.get_id

    # ok: AIK_ruby_check-sql
    titbit = Titbit.find_by("id" => params[:entity_id].squish, "channel_code" => "instagram", 'adminUpdates.feed_matches' => {'$ne' => nil})

	  ## (in this case ruby gives back an array, which is safe)
    auth_session = params[:auth]
    # ok: AIK_ruby_check-sql 
    user = User.kept.find_by(auth_session[:user_attributes].slice("id"))

    auth_session = params[:auth]
    # ruleid: AIK_ruby_check-sql
    user = User.kept.find_by(auth_session[:user_attributes].slice(0))
  end

  TOTALLY_SAFE = "some safe string"

  def test_constant_interpolation
    #ok: AIK_ruby_check-sql
    Product.first("blah = #{TOTALLY_SAFE}")
  end

# Leave previous test as is

# https://github.com/semgrep/semgrep-rules/blob/develop/ruby/rails/security/brakeman/AIK_ruby_check-sql.rb
class Product < ActiveRecord::Base
  def test_find_order
    # (not exploitable)
    #ok: AIK_ruby_check-sql
    Product.find(:all, :order => params[:order])
    #ok: AIK_ruby_check-sql
    # (not exploitable)
    Product.find(:all, :conditions => 'admin = 1', :order => "name #{params[:order]}")
  end

  def test_find_group
    #todoruleid: AIK_ruby_check-sql
    Product.find(:all, :conditions => 'admin = 1', :group => params[:group])
    #todoruleid: AIK_ruby_check-sql
    Product.find(:all, :conditions => 'admin = 1', :group => "something, #{params[:group]}")
  end

  def test_find_having
    #ruleid: AIK_ruby_check-sql
    Product.find(:first, :conditions => 'admin = 1', :having => "x = #{params[:having]}")

    #ok: AIK_ruby_check-sql
    Product.find(:first, :conditions => 'admin = 1', :having => { :x => params[:having]})

    #ok: AIK_ruby_check-sql
    Product.find(:first, :conditions => ['name = ?', params[:name]], :having => [ 'x = ?', params[:having]])

    #ruleid: AIK_ruby_check-sql
    Product.find(:first, :conditions => ['name = ?', params[:name]], :having => [ "admin = ? and x = #{params[:having]}", cookies[:admin]])
    #ruleid: AIK_ruby_check-sql
    Product.find(:first, :conditions => ['name = ?', params[:name]], :having => [ "admin = ? and x = '" + params[:having] + "'", cookies[:admin]])
  end

  def test_find_joins
    #ok: AIK_ruby_check-sql
    Product.find(:first, :conditions => 'admin = 1', :joins => "LEFT JOIN comments ON comments.post_id = id")

    #todoruleid: AIK_ruby_check-sql
    Product.find(:first, :conditions => 'admin = 1', :joins => "LEFT JOIN comments ON comments.#{params[:join]} = id")

    #ok: AIK_ruby_check-sql
    Product.find(:first, :conditions => 'admin = 1', :joins => [:x, :y])

    #todoruleid: AIK_ruby_check-sql
    Product.find(:first, :conditions => 'admin = 1', :joins => ["LEFT JOIN comments ON comments.#{params[:join]} = id", :x, :y])
  end

  def test_find_select
    #ok: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :select => "name")

    #todoruleid: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :select => params[:column])
    #todoruleid: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :select => "name, #{params[:column]}")
    #todoruleid: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :select => "name, " + params[:column])
  end

  def test_find_from
    #ok: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :from => "users")

    #todoruleid: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :from => params[:table])
    #todoruleid: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :from => "#{params[:table]}")
  end

  def test_find_lock
    #ok: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :lock => true)

    #todoruleid: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :lock => params[:lock])
    #todoruleid: AIK_ruby_check-sql
    Product.find(:last, :conditions => 'admin = 1', :lock => "LOCK #{params[:lock]}")
  end

  def test_where
    #ok: AIK_ruby_check-sql
    Product.where("admin = 1")
    #ok: AIK_ruby_check-sql
    Product.where("admin = ?", params[:admin])
    #ok: AIK_ruby_check-sql
    Product.where(["admin = ?", params[:admin]])
    #ok: AIK_ruby_check-sql
    Product.where(["admin = :admin", { :admin => params[:admin] }])
    #ok: AIK_ruby_check-sql
    Product.where(:admin => params[:admin])
    #ok: AIK_ruby_check-sql
    Product.where(:admin => params[:admin], :some_param => params[:some_param])

    #ruleid: AIK_ruby_check-sql
    Product.where("admin = '#{params[:admin]}'").first
    #ok: AIK_ruby_check-sql
    Product.where(["admin = ? AND user_name = #{@name}", params[:admin]])
  end

  TOTALLY_SAFE = "some safe string"

  def test_constant_interpolation
    #ok: AIK_ruby_check-sql
    Product.first("blah = #{TOTALLY_SAFE}")
  end

  def test_local_interpolation
    #this is a weak finding and should be covered by a different rule
    #ok: AIK_ruby_check-sql
    Product.first("blah = #{local_var}")
  end

  def test_conditional_args_in_sql
    # can't confirm
    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{something ? params[:blah] : TOTALLY_SAFE}'")

    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{params[:blah] ? 1 : 0}'")
    
    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{params[:blah] ? params[:blah] : 0}'")

    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{params[:blah] ? 1 : params[:blah]}'")
  end

  def test_params_in_args
    # can't confirm
    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{something(params[:blah])}'")
  end

  def test_params_to_i
    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{params[:id].to_i}'")
  end

  def test_more_if_statements
    if some_condition
      x = params[:x]
    else
      x = "BLAH"
    end

    y = if some_other_condition
      params[:x]
      "blah"
    else
      params[:y]
      "blah"
    end

    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{x}'")

    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{y}'")
    #ok: AIK_ruby_check-sql
    Product.where("blah = 1").group(y)
  end

  def test_calculations
    #ruleid: AIK_ruby_check-sql
    Product.calculate(:count, :all, :conditions => "blah = '#{params[:blah]}'")
    #todoruleid: AIK_ruby_check-sql
    Product.minimum(:price, :conditions => "blah = #{params[:blach]}")
    #todoruleid: AIK_ruby_check-sql
    Product.maximum(:price, :group => params[:columns])
    #todoruleid: AIK_ruby_check-sql
    Product.average(:price, :conditions => ["blah = #{params[:columns]} and x = ?", x])
    #todoruleid: AIK_ruby_check-sql
    Product.sum(params[:columns])
  end

  def test_select
    #ok: AIK_ruby_check-sql
    Product.select([:price, :sku])

    #todoruleid: AIK_ruby_check-sql
    Product.select params[:columns]
  end

  def test_conditional_in_options
    x = params[:x] == y ? "created_at ASC" : "created_at DESC"
    z = params[:y] == y ? "safe" : "totally safe"

    #ok: AIK_ruby_check-sql
    Product.all(:order => x, :having => z, :select => z, :from => z,
                :group => z)
  end

  def test_or_interpolation
    #ok: AIK_ruby_check-sql
    Product.where("blah = #{1 or 2}")
  end

  def test_params_to_f
    #ok: AIK_ruby_check-sql
    Product.last("blah = '#{params[:id].to_f}'")
  end

  def test_interpolation_in_first_arg
    #ruleid: AIK_ruby_check-sql
    Product.where("x = #{params[:x]} AND y = ?", y)
  end

  def test_to_sql_interpolation
    #ok: AIK_ruby_check-sql
    prices = Product.select(:price).where("created_at < :time").to_sql
    #ok: AIK_ruby_check-sql
    where("price IN (#{prices}) OR whatever", :price => some_price)
  end
end

# https://github.com/semgrep/semgrep-rules/blob/develop/ruby/rails/security/injection/AIK_ruby_check-sql.rb
class UsersController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @user = User.new
  end


  def update1
    message = false
    # ruleid:AIK_ruby_check-sql
    user = User.find(:first, :conditions => "user_id = '#{params[:user][:user_id]}'")
    user.skip_user_id_assign = true
    user.update_attributes(params[:user].reject { |k| k == ("password" || "password_confirmation") || "user_id" })
    pass = params[:user][:password]
    user.password = pass if !(pass.blank?)
    message = true if user.save!
    respond_to do |format|
      format.html { redirect_to user_account_settings_path(:user_id => current_user.user_id) }
      format.json { render :json => {:msg => message ? "success" : "false "} }
    end
  end


  def update2
    message = false

    # ruleid:AIK_ruby_check-sql
    user = User.where("user_id = '#{params[:user][:id]}'")[0]

    if user
      user.update_attributes(user_params_without_password)
      if params[:user][:password].present? && (params[:user][:password] == params[:user][:password_confirmation])
        user.password = params[:user][:password]
      end
      message = true if user.save!
      respond_to do |format|
        format.html { redirect_to user_account_settings_path(user_id: current_user.id) }
        format.json { render json: {msg: message ? "success" : "false "} }
      end
    else
      flash[:error] = "Could not update user!"
      redirect_to user_account_settings_path(user_id: current_user.id)
    end
  end

  def test3
    # ruleid:AIK_ruby_check-sql
    records = ActiveRecord::Base.connection.execute("INSERT INTO person (name) VALUES ('%s')" % params[:user])
    redirect_to '/'
  end

  def test4
    # ruleid:AIK_ruby_check-sql
    records = ActiveRecord::Base.connection.execute(Kernel::sprintf("SELECT FROM person WHERE name='%s'", params[:user]))
    redirect_to '/'
  end

  def test5
    # ruleid:AIK_ruby_check-sql
    records = ActiveRecord::Base.connection.execute("SELECT FROM person WHERE name='" + params[:user] + "'")
    redirect_to '/'
  end

  def ok_test1
    # ok:AIK_ruby_check-sql
    message = "this is just a message ! %s" % params[:user]
    redirect_to '/'
  end

  def ok_test2
    # ok:AIK_ruby_check-sql
    message = Kernel::sprintf("this message is ok: '%s'", params[:user])
    redirect_to '/'
  end

  def ok_test3
    # ok:AIK_ruby_check-sql
    records = "this is ok!" + params[:user] + "'"
    redirect_to '/'
  end

  def ok_test4
    # ok:AIK_ruby_check-sql
    user = User.where("user_id = ?", "#{params[:user][:id]}")[0]
  end

  def ok_test5
    redirect_url = params[:redirect]
    # ok:AIK_ruby_check-sql
    redirect_to "#{authenticator_domain}/application-name/landing?redirect_path=#{redirect_url}"
  end

  def ok_test6
    # ok:AIK_ruby_check-sql
    user = User.where(user_id: params[:user_id])[0]
    # ok:AIK_ruby_check-sql
    user = User.where(params.slice(:user_id))[0]
  end

end

# Aikido special cases
class UsersController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @user = User.new
  end

  def update1
    # ruleid:AIK_ruby_check-sql
    User.where("name = '#{params[:name]}'")
    # ok:AIK_ruby_check-sql
    @user.update(name: "#{params[:name]}")
    # ruleid:AIK_ruby_check-sql
    User.delete_by("id = #{params[:id]}")
    end
  end
end
